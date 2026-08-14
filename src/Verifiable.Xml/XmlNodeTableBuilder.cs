using System.Buffers;
using System.Text;

namespace Verifiable.Xml;

/// <summary>
/// Builds an <see cref="XmlNodeTable"/> in one pass over an <see cref="XmlSpanReader"/>, performing the
/// processing <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
/// section 2.1 requires of the XML processor that prepares the XPath data model: line-end normalization
/// per <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
/// section 2.11, attribute-value normalization per the CDATA rule of section 3.3.3, replacement of CDATA
/// sections with their character content, resolution of character and predefined entity references, and
/// coalescing of consecutive character data into single text nodes. Namespace processing enforces
/// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third Edition)</see>
/// in full. Every buffer is rented from the caller-supplied pool.
/// </summary>
internal sealed class XmlNodeTableBuilder: IDisposable
{
    /// <summary>The FNV-1a 64-bit offset basis.</summary>
    private const ulong FnvOffsetBasis = 14695981039346656037UL;

    /// <summary>The FNV-1a 64-bit prime.</summary>
    private const ulong FnvPrime = 1099511628211UL;

    /// <summary>The initial bucket count of <see cref="NamespaceScopeBuckets"/>; a power of two so the bucket of a hash is a mask.</summary>
    private const int InitialNamespaceScopeBucketCount = 64;

    /// <summary>The document tree nodes, in document order.</summary>
    private PooledStructList<NodeRecord> Nodes { get; }

    /// <summary>The attribute records, contiguous per element in document order.</summary>
    private PooledStructList<AttributeRecord> Attributes { get; }

    /// <summary>The namespace declaration records, contiguous per element in document order.</summary>
    private PooledStructList<NamespaceDeclarationRecord> NamespaceDeclarations { get; }

    /// <summary>The string heap all records reference into.</summary>
    private PooledStructList<byte> StringHeap { get; }

    /// <summary>The open-element stack.</summary>
    private PooledStructList<ElementStackEntry> ElementStack { get; }

    /// <summary>The in-scope namespace declaration stack.</summary>
    private PooledStructList<NamespaceScopeEntry> NamespaceScope { get; }

    /// <summary>
    /// The hash-bucket heads over <see cref="NamespaceScope"/>: the stack index of the most recently
    /// pushed entry of each bucket chain, or -1 for an empty bucket, keyed by the FNV-1a hash of the
    /// declared prefix. The chains make prefix resolution a bucket walk, so name resolution stays
    /// near-linear in the declaration count.
    /// </summary>
    private PooledStructList<int> NamespaceScopeBuckets { get; }

    /// <summary>The attributes of the start-tag currently being processed.</summary>
    private PooledStructList<StagedAttribute> StagedAttributes { get; }

    /// <summary>The decoded character data accumulated for the pending text node.</summary>
    private PooledStructList<byte> TextAccumulator { get; }

    /// <summary>Scratch hash keys for duplicate detection.</summary>
    private PooledStructList<ulong> HashKeyScratch { get; }

    /// <summary>Scratch indices for duplicate detection.</summary>
    private PooledStructList<int> HashIndexScratch { get; }

    /// <summary>Working-span name offsets of the attributes added for the current element, for refusal reporting.</summary>
    private PooledStructList<int> AttributeSourceOffsets { get; }

    /// <summary>Heap offset of the interned <c>xml</c> namespace URI.</summary>
    private int xmlNamespaceUriOffset;

    /// <summary>Whether the core lists were transferred to a table.</summary>
    private bool isOwnershipTransferred;

    /// <summary>Whether this builder has been disposed.</summary>
    private bool isDisposed;


    /// <summary>
    /// Creates a builder whose buffers are rented from the given pool, sized from the document length.
    /// </summary>
    /// <param name="pool">The pool every buffer is rented from.</param>
    /// <param name="documentLength">The document length in octets, used for initial sizing.</param>
    public XmlNodeTableBuilder(MemoryPool<byte> pool, int documentLength)
    {
        int heapHint = Math.Clamp(documentLength, 256, 65536);
        Nodes = new PooledStructList<NodeRecord>(pool, 64);
        Attributes = new PooledStructList<AttributeRecord>(pool, 32);
        NamespaceDeclarations = new PooledStructList<NamespaceDeclarationRecord>(pool, 16);
        StringHeap = new PooledStructList<byte>(pool, heapHint);
        ElementStack = new PooledStructList<ElementStackEntry>(pool, 64);
        NamespaceScope = new PooledStructList<NamespaceScopeEntry>(pool, 32);
        NamespaceScopeBuckets = new PooledStructList<int>(pool, InitialNamespaceScopeBucketCount);
        for(int i = 0; i < InitialNamespaceScopeBucketCount; ++i)
        {
            NamespaceScopeBuckets.Add(-1);
        }

        StagedAttributes = new PooledStructList<StagedAttribute>(pool, 16);
        TextAccumulator = new PooledStructList<byte>(pool, 256);
        HashKeyScratch = new PooledStructList<ulong>(pool, 16);
        HashIndexScratch = new PooledStructList<int>(pool, 16);
        AttributeSourceOffsets = new PooledStructList<int>(pool, 16);
    }


    /// <summary>
    /// The node index new nodes attach to: the innermost open element, or the root node.
    /// </summary>
    private int CurrentParent => ElementStack.Count == 0 ? 0 : ElementStack[ElementStack.Count - 1].NodeIndex;


    /// <summary>
    /// Runs the single build pass over the working UTF-8 document.
    /// </summary>
    /// <param name="working">The UTF-8 document octets, validated and without a byte order mark.</param>
    /// <param name="baseOffset">The offset added to positions so refusals land in input coordinates.</param>
    /// <param name="detectedEncoding">The encoding the front end detected, checked against the XML declaration.</param>
    /// <param name="error">The refusal when building fails.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    public bool TryBuild(ReadOnlySpan<byte> working, long baseOffset, DetectedXmlEncoding detectedEncoding, out XmlReadError error)
    {
        error = default;
        xmlNamespaceUriOffset = StringHeap.AddRange(XmlCharacters.XmlNamespaceUri);
        Nodes.Add(new NodeRecord
        {
            Kind = (int)XmlNodeKind.Root,
            Parent = -1,
            FirstChild = -1,
            LastChild = -1,
            NextSibling = -1
        });
        var reader = new XmlSpanReader(working, baseOffset);
        while(reader.TryRead(out XmlToken token))
        {
            bool isHandled = token.Kind switch
            {
                XmlTokenKind.XmlDeclaration => TryHandleXmlDeclaration(ref reader, detectedEncoding, ref error),
                XmlTokenKind.ElementStart => TryHandleElementStart(working, baseOffset, in token, ref reader, ref error),
                XmlTokenKind.ElementEnd => TryHandleElementEnd(working, in token, ref error),
                XmlTokenKind.Text => TryDecodeContentInto(TextAccumulator, token.Value, token.ValueByteOffset, ref error),
                XmlTokenKind.CDataSection => AppendCDataContent(in token),
                XmlTokenKind.Comment => AppendCommentNode(in token),
                XmlTokenKind.ProcessingInstruction => AppendProcessingInstructionNode(in token),
                XmlTokenKind.WhitespaceOutsideRoot => true,
                _ => true
            };
            if(!isHandled)
            {
                return false;
            }
        }

        if(reader.HasFailed)
        {
            error = reader.Error;

            return false;
        }

        return true;
    }


    /// <summary>
    /// Creates the table from the built lists and takes over their ownership.
    /// </summary>
    /// <returns>The finished table.</returns>
    public XmlNodeTable TransferToTable()
    {
        isOwnershipTransferred = true;

        return new XmlNodeTable(Nodes, Attributes, NamespaceDeclarations, StringHeap, xmlNamespaceUriOffset, XmlCharacters.XmlNamespaceUri.Length);
    }


    /// <summary>
    /// Returns the scratch buffers to the pool, and the core lists too unless a table took them over.
    /// </summary>
    public void Dispose()
    {
        if(isDisposed)
        {
            return;
        }

        isDisposed = true;
        ElementStack.Dispose();
        NamespaceScope.Dispose();
        NamespaceScopeBuckets.Dispose();
        StagedAttributes.Dispose();
        TextAccumulator.Dispose();
        HashKeyScratch.Dispose();
        HashIndexScratch.Dispose();
        AttributeSourceOffsets.Dispose();
        if(!isOwnershipTransferred)
        {
            Nodes.Dispose();
            Attributes.Dispose();
            NamespaceDeclarations.Dispose();
            StringHeap.Dispose();
        }
    }


    /// <summary>
    /// Checks the XML declaration's encoding name against the detected encoding, per the
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.3.3 fatal-error rules for an entity presented in an encoding other than the one named in
    /// its declaration or in an encoding the processor is unable to process.
    /// </summary>
    /// <param name="reader">The reader that produced the declaration token.</param>
    /// <param name="detectedEncoding">The encoding the front end detected.</param>
    /// <param name="error">The refusal when the declaration is inconsistent.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    private static bool TryHandleXmlDeclaration(ref XmlSpanReader reader, DetectedXmlEncoding detectedEncoding, ref XmlReadError error)
    {
        ReadOnlySpan<byte> declared = reader.DeclaredEncoding;
        if(declared.IsEmpty)
        {
            return true;
        }

        bool isDeclaredUtf8 = Ascii.EqualsIgnoreCase(declared, "UTF-8"u8);
        bool isDeclaredUtf16 = Ascii.EqualsIgnoreCase(declared, "UTF-16"u8);
        bool isConsistent = (isDeclaredUtf8 && detectedEncoding == DetectedXmlEncoding.Utf8)
            || (isDeclaredUtf16 && detectedEncoding != DetectedXmlEncoding.Utf8);
        if(!isConsistent)
        {
            error = new XmlReadError(XmlReadFailure.InvalidEncoding, reader.DeclaredEncodingByteOffset);

            return false;
        }

        return true;
    }


    /// <summary>
    /// Appends CDATA content to the pending text node, applying only the line-end normalization of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.11: within a CDATA section only the section close is recognized as markup, so references
    /// are not resolved.
    /// </summary>
    /// <param name="token">The CDATA token.</param>
    /// <returns>Always <see langword="true"/>.</returns>
    private bool AppendCDataContent(in XmlToken token)
    {
        AppendLineNormalized(TextAccumulator, token.Value);

        return true;
    }


    /// <summary>
    /// Flushes pending text and appends a comment node.
    /// </summary>
    /// <param name="token">The comment token.</param>
    /// <returns>Always <see langword="true"/>.</returns>
    private bool AppendCommentNode(in XmlToken token)
    {
        FlushText();
        int valueOffset = StringHeap.Count;
        AppendLineNormalized(StringHeap, token.Value);
        AppendNode(new NodeRecord
        {
            Kind = (int)XmlNodeKind.Comment,
            Parent = CurrentParent,
            FirstChild = -1,
            LastChild = -1,
            NextSibling = -1,
            ValueOffset = valueOffset,
            ValueLength = StringHeap.Count - valueOffset
        });

        return true;
    }


    /// <summary>
    /// Flushes pending text and appends a processing instruction node.
    /// </summary>
    /// <param name="token">The processing instruction token.</param>
    /// <returns>Always <see langword="true"/>.</returns>
    private bool AppendProcessingInstructionNode(in XmlToken token)
    {
        FlushText();
        int targetOffset = StringHeap.AddRange(token.Name);
        int valueOffset = StringHeap.Count;
        AppendLineNormalized(StringHeap, token.Value);
        AppendNode(new NodeRecord
        {
            Kind = (int)XmlNodeKind.ProcessingInstruction,
            Parent = CurrentParent,
            FirstChild = -1,
            LastChild = -1,
            NextSibling = -1,
            LocalOffset = targetOffset,
            LocalLength = token.Name.Length,
            ValueOffset = valueOffset,
            ValueLength = StringHeap.Count - valueOffset
        });

        return true;
    }


    /// <summary>
    /// Reads the staged attributes of a start-tag and completes the element: uniqueness, namespace
    /// declarations, name resolution and value normalization.
    /// </summary>
    /// <param name="working">The working document span.</param>
    /// <param name="baseOffset">The offset added to working positions for refusal reporting.</param>
    /// <param name="token">The element-start token.</param>
    /// <param name="reader">The reader, positioned inside the start-tag.</param>
    /// <param name="error">The refusal when handling fails.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    private bool TryHandleElementStart(ReadOnlySpan<byte> working, long baseOffset, in XmlToken token, ref XmlSpanReader reader, ref XmlReadError error)
    {
        FlushText();
        StagedAttributes.Truncate(0);
        int qnameOffset = (int)(token.ByteOffset - baseOffset) + 1;
        int qnameLength = token.Name.Length;
        bool isEmptyElement;
        while(true)
        {
            if(!reader.TryRead(out XmlToken next))
            {
                error = reader.Error;

                return false;
            }

            if(next.Kind == XmlTokenKind.Attribute)
            {
                StagedAttributes.Add(new StagedAttribute
                {
                    NameOffset = (int)(next.ByteOffset - baseOffset),
                    NameLength = next.Name.Length,
                    ValueOffset = (int)(next.ValueByteOffset - baseOffset),
                    ValueLength = next.Value.Length
                });
                continue;
            }

            isEmptyElement = next.Kind == XmlTokenKind.ElementEmptyClose;
            break;
        }

        return TryCompleteElement(working, baseOffset, qnameOffset, qnameLength, isEmptyElement, ref error);
    }


    /// <summary>
    /// Completes an element whose whole tag has been read: refuses duplicate attribute names per the
    /// Unique Att Spec well-formedness constraint of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 3.1,
    /// processes namespace declarations, resolves the element and attribute names against the in-scope
    /// declarations and refuses duplicate expanded names per
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 6.3.
    /// </summary>
    /// <param name="working">The working document span.</param>
    /// <param name="baseOffset">The offset added to working positions for refusal reporting.</param>
    /// <param name="qnameOffset">Offset of the element's qualified name in the working span.</param>
    /// <param name="qnameLength">Length of the element's qualified name.</param>
    /// <param name="isEmptyElement">Whether the tag was an empty-element tag.</param>
    /// <param name="error">The refusal when completion fails.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    private bool TryCompleteElement(ReadOnlySpan<byte> working, long baseOffset, int qnameOffset, int qnameLength, bool isEmptyElement, ref XmlReadError error)
    {
        if(!TryCheckLiteralDuplicates(working, baseOffset, ref error))
        {
            return false;
        }

        int elementIndex = AppendNode(new NodeRecord
        {
            Kind = (int)XmlNodeKind.Element,
            Parent = CurrentParent,
            FirstChild = -1,
            LastChild = -1,
            NextSibling = -1
        });
        int scopeMark = NamespaceScope.Count;
        int declarationFirst = NamespaceDeclarations.Count;
        for(int i = 0; i < StagedAttributes.Count; ++i)
        {
            StagedAttribute staged = StagedAttributes[i];
            ReadOnlySpan<byte> name = working.Slice(staged.NameOffset, staged.NameLength);
            int colonIndex = name.IndexOf((byte)':');
            bool isDefaultDeclaration = colonIndex < 0 && name.SequenceEqual(XmlCharacters.XmlnsPrefix);
            bool isPrefixedDeclaration = colonIndex >= 0 && name[..colonIndex].SequenceEqual(XmlCharacters.XmlnsPrefix);
            if(!isDefaultDeclaration && !isPrefixedDeclaration)
            {
                continue;
            }

            if(!TryAppendNamespaceDeclaration(working, baseOffset, staged, elementIndex, isPrefixedDeclaration ? name[(colonIndex + 1)..] : default, ref error))
            {
                return false;
            }
        }

        int declarationCount = NamespaceDeclarations.Count - declarationFirst;
        ReadOnlySpan<byte> qname = working.Slice(qnameOffset, qnameLength);
        int elementColon = qname.IndexOf((byte)':');
        ReadOnlySpan<byte> elementPrefix = elementColon < 0 ? default : qname[..elementColon];
        ReadOnlySpan<byte> elementLocal = elementColon < 0 ? qname : qname[(elementColon + 1)..];
        if(!TryResolveName(elementPrefix, isElementName: true, baseOffset + qnameOffset, out int namespaceOffset, out int namespaceLength, ref error))
        {
            return false;
        }

        int elementPrefixOffset = StringHeap.AddRange(elementPrefix);
        int elementLocalOffset = StringHeap.AddRange(elementLocal);
        int attributeFirst = Attributes.Count;
        AttributeSourceOffsets.Truncate(0);
        for(int i = 0; i < StagedAttributes.Count; ++i)
        {
            StagedAttribute staged = StagedAttributes[i];
            ReadOnlySpan<byte> name = working.Slice(staged.NameOffset, staged.NameLength);
            int colonIndex = name.IndexOf((byte)':');
            bool isDefaultDeclaration = colonIndex < 0 && name.SequenceEqual(XmlCharacters.XmlnsPrefix);
            bool isPrefixedDeclaration = colonIndex >= 0 && name[..colonIndex].SequenceEqual(XmlCharacters.XmlnsPrefix);
            if(isDefaultDeclaration || isPrefixedDeclaration)
            {
                continue;
            }

            ReadOnlySpan<byte> attributePrefix = colonIndex < 0 ? default : name[..colonIndex];
            ReadOnlySpan<byte> attributeLocal = colonIndex < 0 ? name : name[(colonIndex + 1)..];
            if(!TryResolveName(attributePrefix, isElementName: false, baseOffset + staged.NameOffset, out int attributeNamespaceOffset, out int attributeNamespaceLength, ref error))
            {
                return false;
            }

            int valueOffset = StringHeap.Count;
            if(!TryDecodeAttributeValueInto(StringHeap, working.Slice(staged.ValueOffset, staged.ValueLength), baseOffset + staged.ValueOffset, ref error))
            {
                return false;
            }

            int valueLength = StringHeap.Count - valueOffset;
            int attributePrefixOffset = StringHeap.AddRange(attributePrefix);
            int attributeLocalOffset = StringHeap.AddRange(attributeLocal);
            Attributes.Add(new AttributeRecord
            {
                Parent = elementIndex,
                PrefixOffset = attributePrefixOffset,
                PrefixLength = attributePrefix.Length,
                LocalOffset = attributeLocalOffset,
                LocalLength = attributeLocal.Length,
                NamespaceOffset = attributeNamespaceOffset,
                NamespaceLength = attributeNamespaceLength,
                ValueOffset = valueOffset,
                ValueLength = valueLength
            });
            AttributeSourceOffsets.Add(staged.NameOffset);
        }

        int attributeCount = Attributes.Count - attributeFirst;
        if(!TryCheckExpandedDuplicates(attributeFirst, attributeCount, baseOffset, ref error))
        {
            return false;
        }

        ref NodeRecord element = ref Nodes[elementIndex];
        element.PrefixOffset = elementPrefixOffset;
        element.PrefixLength = elementPrefix.Length;
        element.LocalOffset = elementLocalOffset;
        element.LocalLength = elementLocal.Length;
        element.NamespaceOffset = namespaceOffset;
        element.NamespaceLength = namespaceLength;
        element.AttributeFirst = attributeFirst;
        element.AttributeCount = attributeCount;
        element.NamespaceDeclarationFirst = declarationFirst;
        element.NamespaceDeclarationCount = declarationCount;
        if(isEmptyElement)
        {
            TruncateNamespaceScope(scopeMark);
        }
        else
        {
            ElementStack.Add(new ElementStackEntry
            {
                NodeIndex = elementIndex,
                NamespaceScopeMark = scopeMark,
                QNameOffset = qnameOffset,
                QNameLength = qnameLength
            });
        }

        return true;
    }


    /// <summary>
    /// Validates and records one namespace declaration attribute, enforcing the Reserved Prefixes and
    /// Namespace Names constraint of
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 3, the No Prefix Undeclaring constraint of section 5, and the relative
    /// namespace URI refusal <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML
    /// 1.0</see> section 2.1 requires.
    /// </summary>
    /// <param name="working">The working document span.</param>
    /// <param name="baseOffset">The offset added to working positions for refusal reporting.</param>
    /// <param name="staged">The staged declaration attribute.</param>
    /// <param name="elementIndex">The owning element's node index.</param>
    /// <param name="declaredPrefix">The prefix being declared; empty for the default namespace.</param>
    /// <param name="error">The refusal when the declaration is invalid.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    private bool TryAppendNamespaceDeclaration(ReadOnlySpan<byte> working, long baseOffset, StagedAttribute staged, int elementIndex, ReadOnlySpan<byte> declaredPrefix, ref XmlReadError error)
    {
        int uriOffset = StringHeap.Count;
        if(!TryDecodeAttributeValueInto(StringHeap, working.Slice(staged.ValueOffset, staged.ValueLength), baseOffset + staged.ValueOffset, ref error))
        {
            return false;
        }

        int uriLength = StringHeap.Count - uriOffset;
        ReadOnlySpan<byte> uri = StringHeap.AsSpan().Slice(uriOffset, uriLength);
        long nameOffset = baseOffset + staged.NameOffset;
        bool isDefaultDeclaration = declaredPrefix.IsEmpty;
        if(!isDefaultDeclaration)
        {
            if(declaredPrefix.SequenceEqual(XmlCharacters.XmlnsPrefix))
            {
                error = new XmlReadError(XmlReadFailure.ReservedPrefixMisuse, nameOffset);

                return false;
            }

            bool isXmlPrefix = declaredPrefix.SequenceEqual(XmlCharacters.XmlPrefix);
            bool isXmlUri = uri.SequenceEqual(XmlCharacters.XmlNamespaceUri);
            if(isXmlPrefix != isXmlUri)
            {
                error = new XmlReadError(XmlReadFailure.ReservedPrefixMisuse, nameOffset);

                return false;
            }

            if(uri.SequenceEqual(XmlCharacters.XmlnsNamespaceUri))
            {
                error = new XmlReadError(XmlReadFailure.ReservedPrefixMisuse, nameOffset);

                return false;
            }

            if(uriLength == 0)
            {
                error = new XmlReadError(XmlReadFailure.PrefixUndeclarationProhibited, nameOffset);

                return false;
            }
        }
        else if(uri.SequenceEqual(XmlCharacters.XmlNamespaceUri) || uri.SequenceEqual(XmlCharacters.XmlnsNamespaceUri))
        {
            error = new XmlReadError(XmlReadFailure.ReservedPrefixMisuse, nameOffset);

            return false;
        }

        if(uriLength > 0 && !XmlCharacters.IsAbsoluteUri(uri))
        {
            error = new XmlReadError(XmlReadFailure.RelativeNamespaceUri, baseOffset + staged.ValueOffset);

            return false;
        }

        int prefixOffset = StringHeap.AddRange(declaredPrefix);
        NamespaceDeclarations.Add(new NamespaceDeclarationRecord
        {
            Parent = elementIndex,
            PrefixOffset = prefixOffset,
            PrefixLength = declaredPrefix.Length,
            UriOffset = uriOffset,
            UriLength = uriLength
        });
        if((NamespaceScope.Count + 1) * 4 > NamespaceScopeBuckets.Count * 3)
        {
            GrowNamespaceScopeBuckets();
        }

        int bucket = (int)(Fnv1a(declaredPrefix, FnvOffsetBasis) & (ulong)(NamespaceScopeBuckets.Count - 1));
        int entryIndex = NamespaceScope.Add(new NamespaceScopeEntry
        {
            PrefixOffset = prefixOffset,
            PrefixLength = declaredPrefix.Length,
            UriOffset = uriOffset,
            UriLength = uriLength,
            Bucket = bucket,
            PreviousInBucket = NamespaceScopeBuckets[bucket]
        });
        NamespaceScopeBuckets[bucket] = entryIndex;

        return true;
    }


    /// <summary>
    /// Resolves a prefix against the in-scope declarations per the Prefix Declared constraint of
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 5, honoring the implicit <c>xml</c> binding of section 3 and namespace
    /// defaulting per section 6.2, under which an unprefixed attribute name never has a namespace.
    /// </summary>
    /// <param name="prefix">The prefix to resolve; empty for an unprefixed name.</param>
    /// <param name="isElementName">Whether the name is an element name, which the default namespace applies to.</param>
    /// <param name="refusalOffset">The offset to report a refusal at.</param>
    /// <param name="namespaceOffset">Heap offset of the resolved namespace URI.</param>
    /// <param name="namespaceLength">Heap length of the resolved namespace URI; zero for none.</param>
    /// <param name="error">The refusal when the prefix cannot be resolved.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    private bool TryResolveName(ReadOnlySpan<byte> prefix, bool isElementName, long refusalOffset, out int namespaceOffset, out int namespaceLength, ref XmlReadError error)
    {
        namespaceOffset = 0;
        namespaceLength = 0;
        if(prefix.IsEmpty)
        {
            if(isElementName && TryLookupNamespace(default, out int defaultOffset, out int defaultLength))
            {
                namespaceOffset = defaultOffset;
                namespaceLength = defaultLength;
            }

            return true;
        }

        if(prefix.SequenceEqual(XmlCharacters.XmlPrefix))
        {
            namespaceOffset = xmlNamespaceUriOffset;
            namespaceLength = XmlCharacters.XmlNamespaceUri.Length;

            return true;
        }

        if(prefix.SequenceEqual(XmlCharacters.XmlnsPrefix))
        {
            error = new XmlReadError(XmlReadFailure.ReservedPrefixMisuse, refusalOffset);

            return false;
        }

        if(TryLookupNamespace(prefix, out int uriOffset, out int uriLength))
        {
            namespaceOffset = uriOffset;
            namespaceLength = uriLength;

            return true;
        }

        error = new XmlReadError(XmlReadFailure.UndeclaredPrefix, refusalOffset);

        return false;
    }


    /// <summary>
    /// Finds the innermost in-scope declaration of a prefix by walking the prefix's hash-bucket chain of
    /// <see cref="NamespaceScopeBuckets"/>: the chain runs from the most recently pushed entry outward,
    /// so the first entry whose prefix octets match is the innermost declaration.
    /// </summary>
    /// <param name="prefix">The prefix; empty for the default namespace.</param>
    /// <param name="uriOffset">Heap offset of the declared URI.</param>
    /// <param name="uriLength">Heap length of the declared URI; zero for the <c>xmlns=""</c> un-declaration.</param>
    /// <returns><see langword="true"/> when a declaration is in scope.</returns>
    private bool TryLookupNamespace(ReadOnlySpan<byte> prefix, out int uriOffset, out int uriLength)
    {
        int bucket = (int)(Fnv1a(prefix, FnvOffsetBasis) & (ulong)(NamespaceScopeBuckets.Count - 1));
        for(int i = NamespaceScopeBuckets[bucket]; i >= 0; i = NamespaceScope[i].PreviousInBucket)
        {
            NamespaceScopeEntry entry = NamespaceScope[i];
            if(StringHeap.AsSpan().Slice(entry.PrefixOffset, entry.PrefixLength).SequenceEqual(prefix))
            {
                uriOffset = entry.UriOffset;
                uriLength = entry.UriLength;

                return true;
            }
        }

        uriOffset = 0;
        uriLength = 0;

        return false;
    }


    /// <summary>
    /// Pops the namespace scope stack back to a mark, unlinking each popped entry from its bucket chain.
    /// The stack's last-in first-out discipline guarantees every popped entry is its chain's head when it
    /// pops, so unlinking is the head restoration alone.
    /// </summary>
    /// <param name="mark">The scope depth to truncate back to.</param>
    private void TruncateNamespaceScope(int mark)
    {
        for(int i = NamespaceScope.Count - 1; i >= mark; --i)
        {
            NamespaceScopeEntry entry = NamespaceScope[i];
            NamespaceScopeBuckets[entry.Bucket] = entry.PreviousInBucket;
        }

        NamespaceScope.Truncate(mark);
    }


    /// <summary>
    /// Doubles the bucket count of <see cref="NamespaceScopeBuckets"/> and re-threads every live scope
    /// entry in push order, which keeps each chain running from the most recently pushed entry outward.
    /// </summary>
    private void GrowNamespaceScopeBuckets()
    {
        int newBucketCount = NamespaceScopeBuckets.Count * 2;
        NamespaceScopeBuckets.Truncate(0);
        for(int i = 0; i < newBucketCount; ++i)
        {
            NamespaceScopeBuckets.Add(-1);
        }

        for(int i = 0; i < NamespaceScope.Count; ++i)
        {
            ref NamespaceScopeEntry entry = ref NamespaceScope[i];
            int bucket = (int)(Fnv1a(StringHeap.AsSpan().Slice(entry.PrefixOffset, entry.PrefixLength), FnvOffsetBasis) & (ulong)(newBucketCount - 1));
            entry.Bucket = bucket;
            entry.PreviousInBucket = NamespaceScopeBuckets[bucket];
            NamespaceScopeBuckets[bucket] = i;
        }
    }


    /// <summary>
    /// Flushes pending text and matches the end-tag name against the open element per the Element Type
    /// Match well-formedness constraint of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 3.1.
    /// </summary>
    /// <param name="working">The working document span.</param>
    /// <param name="token">The end-tag token.</param>
    /// <param name="error">The refusal when the names differ.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    private bool TryHandleElementEnd(ReadOnlySpan<byte> working, in XmlToken token, ref XmlReadError error)
    {
        FlushText();
        ElementStackEntry top = ElementStack[ElementStack.Count - 1];
        if(!token.Name.SequenceEqual(working.Slice(top.QNameOffset, top.QNameLength)))
        {
            error = new XmlReadError(XmlReadFailure.MismatchedTag, token.ByteOffset + 2);

            return false;
        }

        TruncateNamespaceScope(top.NamespaceScopeMark);
        ElementStack.Truncate(ElementStack.Count - 1);

        return true;
    }


    /// <summary>
    /// Emits the pending coalesced text as one text node, so all consecutive character data lands in a
    /// single node per <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
    /// section 2.1. No node is created for empty content: text nodes are never empty in the XPath data
    /// model.
    /// </summary>
    private void FlushText()
    {
        if(TextAccumulator.Count == 0)
        {
            return;
        }

        int valueOffset = StringHeap.AddRange(TextAccumulator.AsSpan());
        AppendNode(new NodeRecord
        {
            Kind = (int)XmlNodeKind.Text,
            Parent = CurrentParent,
            FirstChild = -1,
            LastChild = -1,
            NextSibling = -1,
            ValueOffset = valueOffset,
            ValueLength = TextAccumulator.Count
        });
        TextAccumulator.Truncate(0);
    }


    /// <summary>
    /// Appends a node and links it as the last child of its parent.
    /// </summary>
    /// <param name="record">The node record; its parent must be set.</param>
    /// <returns>The index of the appended node.</returns>
    private int AppendNode(in NodeRecord record)
    {
        int index = Nodes.Add(in record);
        ref NodeRecord parent = ref Nodes[record.Parent];
        if(parent.FirstChild < 0)
        {
            parent.FirstChild = index;
        }
        else
        {
            Nodes[parent.LastChild].NextSibling = index;
        }

        parent.LastChild = index;

        return index;
    }


    /// <summary>
    /// Refuses two attributes with the same literal name in one tag, the Unique Att Spec well-formedness
    /// constraint of <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth
    /// Edition)</see> section 3.1. Detection hashes every name and compares octets only within equal-hash
    /// runs, so adversarial attribute counts stay near-linear.
    /// </summary>
    /// <param name="working">The working document span.</param>
    /// <param name="baseOffset">The offset added to working positions for refusal reporting.</param>
    /// <param name="error">The refusal when a duplicate exists.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    private bool TryCheckLiteralDuplicates(ReadOnlySpan<byte> working, long baseOffset, ref XmlReadError error)
    {
        int count = StagedAttributes.Count;
        if(count < 2)
        {
            return true;
        }

        HashKeyScratch.Truncate(0);
        HashIndexScratch.Truncate(0);
        for(int i = 0; i < count; ++i)
        {
            StagedAttribute staged = StagedAttributes[i];
            HashKeyScratch.Add(Fnv1a(working.Slice(staged.NameOffset, staged.NameLength), FnvOffsetBasis));
            HashIndexScratch.Add(i);
        }

        Span<ulong> keys = HashKeyScratch.AsMutableSpan();
        Span<int> indices = HashIndexScratch.AsMutableSpan();
        keys.Sort(indices);
        for(int i = 1; i < count; ++i)
        {
            for(int j = i - 1; j >= 0 && keys[j] == keys[i]; --j)
            {
                StagedAttribute first = StagedAttributes[indices[j]];
                StagedAttribute second = StagedAttributes[indices[i]];
                bool isDuplicate = working.Slice(first.NameOffset, first.NameLength)
                    .SequenceEqual(working.Slice(second.NameOffset, second.NameLength));
                if(isDuplicate)
                {
                    error = new XmlReadError(XmlReadFailure.DuplicateAttribute, baseOffset + Math.Max(first.NameOffset, second.NameOffset));

                    return false;
                }
            }
        }

        return true;
    }


    /// <summary>
    /// Refuses two attributes of one element whose expanded names are equal after namespace resolution,
    /// the Attributes Unique constraint of
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 6.3: qualified names with the same local part and with prefixes bound to
    /// identical namespace names.
    /// </summary>
    /// <param name="attributeFirst">Index of the element's first attribute record.</param>
    /// <param name="attributeCount">Number of attribute records the element owns.</param>
    /// <param name="baseOffset">The offset added to working positions for refusal reporting.</param>
    /// <param name="error">The refusal when a duplicate exists.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    private bool TryCheckExpandedDuplicates(int attributeFirst, int attributeCount, long baseOffset, ref XmlReadError error)
    {
        if(attributeCount < 2)
        {
            return true;
        }

        HashKeyScratch.Truncate(0);
        HashIndexScratch.Truncate(0);
        ReadOnlySpan<byte> heap = StringHeap.AsSpan();
        for(int i = 0; i < attributeCount; ++i)
        {
            AttributeRecord record = Attributes[attributeFirst + i];
            ulong hash = Fnv1a(heap.Slice(record.NamespaceOffset, record.NamespaceLength), FnvOffsetBasis);
            hash *= FnvPrime;
            hash = Fnv1a(heap.Slice(record.LocalOffset, record.LocalLength), hash);
            HashKeyScratch.Add(hash);
            HashIndexScratch.Add(i);
        }

        Span<ulong> keys = HashKeyScratch.AsMutableSpan();
        Span<int> indices = HashIndexScratch.AsMutableSpan();
        keys.Sort(indices);
        for(int i = 1; i < attributeCount; ++i)
        {
            for(int j = i - 1; j >= 0 && keys[j] == keys[i]; --j)
            {
                AttributeRecord first = Attributes[attributeFirst + indices[j]];
                AttributeRecord second = Attributes[attributeFirst + indices[i]];
                bool isDuplicate = heap.Slice(first.NamespaceOffset, first.NamespaceLength)
                        .SequenceEqual(heap.Slice(second.NamespaceOffset, second.NamespaceLength))
                    && heap.Slice(first.LocalOffset, first.LocalLength)
                        .SequenceEqual(heap.Slice(second.LocalOffset, second.LocalLength));
                if(isDuplicate)
                {
                    int laterSourceOffset = Math.Max(AttributeSourceOffsets[indices[j]], AttributeSourceOffsets[indices[i]]);
                    error = new XmlReadError(XmlReadFailure.DuplicateAttribute, baseOffset + laterSourceOffset);

                    return false;
                }
            }
        }

        return true;
    }


    /// <summary>
    /// Decodes character data into the destination: line ends normalized per
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.11 by translating <c>#xD #xA</c> and any lone <c>#xD</c> to <c>#xA</c>, and character and
    /// predefined entity references resolved per sections 4.1 and 4.4.2.
    /// </summary>
    /// <param name="destination">The buffer decoded content is appended to.</param>
    /// <param name="raw">The raw character data.</param>
    /// <param name="rawBaseOffset">The input offset of the raw data for refusal reporting.</param>
    /// <param name="error">The refusal when decoding fails.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    private static bool TryDecodeContentInto(PooledStructList<byte> destination, ReadOnlySpan<byte> raw, long rawBaseOffset, ref XmlReadError error)
    {
        int i = 0;
        while(i < raw.Length)
        {
            byte octet = raw[i];
            if(octet == 0x0D)
            {
                destination.Add(0x0A);
                i += i + 1 < raw.Length && raw[i + 1] == 0x0A ? 2 : 1;
                continue;
            }

            if(octet == (byte)'&')
            {
                if(!TryAppendReference(destination, raw, ref i, rawBaseOffset, ref error))
                {
                    return false;
                }

                continue;
            }

            destination.Add(octet);
            i++;
        }

        return true;
    }


    /// <summary>
    /// Decodes an attribute value into the destination per the CDATA normalization rule of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 3.3.3: line ends are first normalized per section 2.11, each literal white space character
    /// then appends a space, a character reference appends the referenced character itself, and an entity
    /// reference appends its replacement text. With no document type declaration every attribute is
    /// treated as CDATA, so no further trimming or space collapsing applies.
    /// </summary>
    /// <param name="destination">The buffer the normalized value is appended to.</param>
    /// <param name="raw">The raw value literal between its quotes.</param>
    /// <param name="rawBaseOffset">The input offset of the raw value for refusal reporting.</param>
    /// <param name="error">The refusal when decoding fails.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    private static bool TryDecodeAttributeValueInto(PooledStructList<byte> destination, ReadOnlySpan<byte> raw, long rawBaseOffset, ref XmlReadError error)
    {
        int i = 0;
        while(i < raw.Length)
        {
            byte octet = raw[i];
            if(octet == 0x0D)
            {
                destination.Add(0x20);
                i += i + 1 < raw.Length && raw[i + 1] == 0x0A ? 2 : 1;
                continue;
            }

            if(octet is 0x0A or 0x09)
            {
                destination.Add(0x20);
                i++;
                continue;
            }

            if(octet == (byte)'&')
            {
                if(!TryAppendReference(destination, raw, ref i, rawBaseOffset, ref error))
                {
                    return false;
                }

                continue;
            }

            destination.Add(octet);
            i++;
        }

        return true;
    }


    /// <summary>
    /// Resolves one reference at the cursor per
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 4.1:
    /// character references are range-checked against production <c>Char</c> per the Legal Character
    /// well-formedness constraint, and entity references beyond the five predefined ones are refused per
    /// the Entity Declared well-formedness constraint for a document with no DTD. Resolution is identical
    /// in character data and attribute values: a referenced character is appended as itself, which is why
    /// a reference to <c>#xD</c>, <c>#xA</c> or <c>#x9</c> survives both the section 2.11 line-end
    /// normalization and the section 3.3.3 white space normalization.
    /// </summary>
    /// <param name="destination">The buffer the resolved character is appended to.</param>
    /// <param name="raw">The raw data containing the reference.</param>
    /// <param name="i">The cursor at the <c>&amp;</c>; advanced past the reference on success.</param>
    /// <param name="rawBaseOffset">The input offset of the raw data for refusal reporting.</param>
    /// <param name="error">The refusal when the reference is invalid.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    private static bool TryAppendReference(PooledStructList<byte> destination, ReadOnlySpan<byte> raw, ref int i, long rawBaseOffset, ref XmlReadError error)
    {
        int ampersand = i;
        if(ampersand + 1 >= raw.Length)
        {
            error = new XmlReadError(XmlReadFailure.MalformedMarkup, rawBaseOffset + ampersand);

            return false;
        }

        if(raw[ampersand + 1] == (byte)'#')
        {
            bool isHex = ampersand + 2 < raw.Length && raw[ampersand + 2] == (byte)'x';
            int digitsStart = ampersand + (isHex ? 3 : 2);
            int cursor = digitsStart;
            long codePoint = 0;
            while(cursor < raw.Length && raw[cursor] != (byte)';')
            {
                int digit = isHex ? HexDigitValue(raw[cursor]) : DecimalDigitValue(raw[cursor]);
                if(digit < 0)
                {
                    error = new XmlReadError(XmlReadFailure.InvalidCharacterReference, rawBaseOffset + ampersand);

                    return false;
                }

                codePoint = codePoint * (isHex ? 16 : 10) + digit;
                if(codePoint > 0x10FFFF)
                {
                    codePoint = 0x110000;
                }

                cursor++;
            }

            if(cursor >= raw.Length || cursor == digitsStart)
            {
                error = new XmlReadError(XmlReadFailure.InvalidCharacterReference, rawBaseOffset + ampersand);

                return false;
            }

            if(codePoint > 0x10FFFF || !XmlCharacters.IsChar((int)codePoint))
            {
                error = new XmlReadError(XmlReadFailure.InvalidCharacterReference, rawBaseOffset + ampersand);

                return false;
            }

            var rune = new Rune((int)codePoint);
            Span<byte> scratch = stackalloc byte[4];
            int written = rune.EncodeToUtf8(scratch);
            destination.AddRange(scratch[..written]);
            i = cursor + 1;

            return true;
        }

        int nameStart = ampersand + 1;
        int nameCursor = nameStart;
        while(nameCursor < raw.Length && raw[nameCursor] != (byte)';')
        {
            nameCursor++;
        }

        if(nameCursor >= raw.Length || nameCursor == nameStart)
        {
            error = new XmlReadError(XmlReadFailure.MalformedMarkup, rawBaseOffset + ampersand);

            return false;
        }

        ReadOnlySpan<byte> entityName = raw[nameStart..nameCursor];
        if(!IsValidEntityName(entityName))
        {
            error = new XmlReadError(XmlReadFailure.MalformedMarkup, rawBaseOffset + ampersand);

            return false;
        }

        if(!XmlCharacters.TryGetPredefinedEntityReplacement(entityName, out byte replacement))
        {
            error = new XmlReadError(XmlReadFailure.UndeclaredEntity, rawBaseOffset + ampersand);

            return false;
        }

        destination.Add(replacement);
        i = nameCursor + 1;

        return true;
    }


    /// <summary>
    /// Tells whether the octets form a colon-free name per production <c>Name</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.3
    /// restricted to <c>NCName</c>, the form entity names take in a namespace-well-formed document per
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 7.
    /// </summary>
    /// <param name="name">The candidate entity name.</param>
    /// <returns><see langword="true"/> when the octets form an <c>NCName</c>.</returns>
    private static bool IsValidEntityName(ReadOnlySpan<byte> name)
    {
        int index = 0;
        bool isFirst = true;
        while(index < name.Length)
        {
            if(Rune.DecodeFromUtf8(name[index..], out Rune rune, out int consumed) != OperationStatus.Done)
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


    /// <summary>
    /// Appends raw octets with the line-end normalization of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.11 applied: <c>#xD #xA</c> and any lone <c>#xD</c> become a single <c>#xA</c>.
    /// </summary>
    /// <param name="destination">The buffer normalized content is appended to.</param>
    /// <param name="raw">The raw octets.</param>
    private static void AppendLineNormalized(PooledStructList<byte> destination, ReadOnlySpan<byte> raw)
    {
        int i = 0;
        while(i < raw.Length)
        {
            byte octet = raw[i];
            if(octet == 0x0D)
            {
                destination.Add(0x0A);
                i += i + 1 < raw.Length && raw[i + 1] == 0x0A ? 2 : 1;
                continue;
            }

            destination.Add(octet);
            i++;
        }
    }


    /// <summary>
    /// The value of a hexadecimal digit octet of production <c>CharRef</c>, or -1.
    /// </summary>
    /// <param name="octet">The octet to interpret.</param>
    /// <returns>The digit value, or -1 when the octet is not a hexadecimal digit.</returns>
    private static int HexDigitValue(byte octet)
    {
        return octet switch
        {
            >= (byte)'0' and <= (byte)'9' => octet - (byte)'0',
            >= (byte)'a' and <= (byte)'f' => octet - (byte)'a' + 10,
            >= (byte)'A' and <= (byte)'F' => octet - (byte)'A' + 10,
            _ => -1
        };
    }


    /// <summary>
    /// The value of a decimal digit octet of production <c>CharRef</c>, or -1.
    /// </summary>
    /// <param name="octet">The octet to interpret.</param>
    /// <returns>The digit value, or -1 when the octet is not a decimal digit.</returns>
    private static int DecimalDigitValue(byte octet)
    {
        return octet is >= (byte)'0' and <= (byte)'9' ? octet - (byte)'0' : -1;
    }


    /// <summary>
    /// Computes the 64-bit FNV-1a hash of the octets from a running state.
    /// </summary>
    /// <param name="data">The octets to hash.</param>
    /// <param name="seed">The running hash state, <see cref="FnvOffsetBasis"/> to start.</param>
    /// <returns>The advanced hash state.</returns>
    private static ulong Fnv1a(ReadOnlySpan<byte> data, ulong seed)
    {
        ulong hash = seed;
        for(int i = 0; i < data.Length; ++i)
        {
            hash ^= data[i];
            hash *= FnvPrime;
        }

        return hash;
    }
}

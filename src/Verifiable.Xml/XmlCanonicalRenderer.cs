using System.Buffers;

namespace Verifiable.Xml;

/// <summary>
/// The canonicalization algorithm family a render pass applies. Each member selects its family's
/// document-subsets policy in <see cref="XmlCanonicalRenderer"/>: which <c>xml:*</c> attributes an element
/// with an omitted parent inherits, per section 2.4 of
/// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> and of
/// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>. The
/// namespace-axis policy is likewise selected per family: the inclusive families render the in-scope axis
/// with superfluous-declaration suppression, the exclusive family the visibly-utilized subset of
/// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
/// 1.0</see> section 3.
/// </summary>
internal enum XmlCanonicalVariant
{
    /// <summary>
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>: an element
    /// with an omitted parent imports the nearest occurrence of every attribute in the <c>xml</c>
    /// namespace from its ancestor axis, per section 2.4.
    /// </summary>
    Inclusive10,

    /// <summary>
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>: an
    /// element with an omitted parent imports only the simple inheritable <c>xml:lang</c> and
    /// <c>xml:space</c>, never <c>xml:id</c>, joins <c>xml:base</c> values of contiguously omitted
    /// ancestors with the join-URI-References function, and treats every other <c>xml</c>-namespace
    /// attribute as ordinary, per section 2.4.
    /// </summary>
    Inclusive11,

    /// <summary>
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see>: an element with an omitted parent imports no <c>xml</c>-namespace attributes — the
    /// ancestor search and copying of Canonical XML "are omitted from the Exclusive XML Canonicalization
    /// method" per section 3 item 1 — and the namespace axis renders by the visibly-utilizes rule of
    /// section 3 items 3 and 4, except for prefixes on the <c>InclusiveNamespaces PrefixList</c>, which
    /// section 3 item 2 hands back to Canonical XML handling.
    /// </summary>
    Exclusive10
}


/// <summary>
/// The processing model of section 2.3 of
/// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> and
/// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see> over an
/// <see cref="XmlNodeTable"/> and an <see cref="XmlNodeSet"/>: nodes render in ascending document order as
/// UTF-8 octets without a byte order mark; an element in the set renders its start tag with the namespace
/// axis sorted lexicographically by prefix with the default namespace first and the attribute axis sorted
/// by namespace URI then local name with the empty URI least; superfluous namespace declarations are
/// suppressed against the nearest rendered ancestor; the <c>xmlns=""</c> emission rule and the
/// <c>xml</c>-prefix suppression rule of section 2.3 apply; text and attribute values escape exactly the
/// characters section 2.3 lists with uppercase hexadecimal character references without leading zeros; and
/// processing instructions and comments outside the document element carry the <c>#xA</c> separators
/// section 2.3 places around them. The document-subsets enhancement of section 2.4 applies to every
/// rendered element whose parent is omitted from the set, with the inheritance policy selected by
/// <see cref="XmlCanonicalVariant"/>. The walk carries the node-set decisions of every open ancestor on
/// its frames and the in-scope namespace bindings in a <see cref="NamespaceRenderContext"/> maintained
/// incrementally during descent, so membership, suppression and inheritance read from the walk state
/// instead of re-deriving the ancestor axis per node.
/// </summary>
internal static class XmlCanonicalRenderer
{
    /// <summary>An attribute render item drawn from the element's own attribute axis.</summary>
    private const int OwnAttributeSource = 0;

    /// <summary>An attribute render item imported from an ancestor per the section 2.4 enhancement.</summary>
    private const int ImportedAttributeSource = 1;

    /// <summary>The synthesized <c>xml:base</c> render item produced by the join-URI-References fixup.</summary>
    private const int SynthesizedXmlBaseSource = 2;


    /// <summary>
    /// One frame of the iterative tree walk, carrying the node-set decisions of its node so descendants
    /// read them in constant time.
    /// </summary>
    private struct RenderFrame
    {
        /// <summary>The element or root node the frame walks the children of.</summary>
        public int NodeIndex;

        /// <summary>The next child to process, or -1 when the children are exhausted.</summary>
        public int NextChild;

        /// <summary>Whether the node renders tags, so its end tag is emitted when the frame pops.</summary>
        public bool IsRendered;

        /// <summary>Whether the node is in the node-set; for the root node, whether the set is the whole-document shape.</summary>
        public bool IsNodeInSet;

        /// <summary>Whether the subtree apex of an element-subtree set is the node or one of its ancestors.</summary>
        public bool IsUnderApex;

        /// <summary>The nearest element at or above the node that is in the node-set, or -1 when none is.</summary>
        public int NearestInSetElement;

        /// <summary>The <see cref="NamespaceRenderContext"/> mark the frame's scope pops back to.</summary>
        public int NamespaceScopeMark;
    }


    /// <summary>
    /// One prefix of the <see cref="NamespaceRenderContext"/>: a reference to a declaration carrying the
    /// prefix octets and the head of the prefix's binding chain.
    /// </summary>
    private struct NamespacePrefixSlot
    {
        /// <summary>The element whose declaration list carries the prefix octets.</summary>
        public int PrefixElement;

        /// <summary>The declaration ordinal within that element.</summary>
        public int PrefixOrdinal;

        /// <summary>The binding stack index of the innermost in-scope binding, or -1 while none is.</summary>
        public int HeadBinding;
    }


    /// <summary>
    /// One pushed namespace binding of the <see cref="NamespaceRenderContext"/>, chaining to the binding
    /// of the same prefix it shadows.
    /// </summary>
    private struct NamespaceBindingEntry
    {
        /// <summary>The slot of the declared prefix.</summary>
        public int SlotIndex;

        /// <summary>The element whose declaration list holds the binding.</summary>
        public int Element;

        /// <summary>The declaration ordinal within that element.</summary>
        public int Ordinal;

        /// <summary>The binding stack index of the shadowed binding of the same slot, or -1.</summary>
        public int PreviousBinding;
    }


    /// <summary>
    /// One <c>xml:base</c> value source of the Canonical XML 1.1 join fixup: the element and attribute
    /// ordinal carrying the value.
    /// </summary>
    private struct XmlBaseValueSource
    {
        /// <summary>The element whose attribute list holds the value.</summary>
        public int Element;

        /// <summary>The attribute ordinal within that element.</summary>
        public int Ordinal;
    }


    /// <summary>
    /// One attribute of the merged render list of the element being rendered: its own attribute, an
    /// imported ancestor attribute, or the synthesized <c>xml:base</c> of the fixup.
    /// </summary>
    private struct AttributeRenderItem
    {
        /// <summary>One of <see cref="OwnAttributeSource"/>, <see cref="ImportedAttributeSource"/> or <see cref="SynthesizedXmlBaseSource"/>.</summary>
        public int Source;

        /// <summary>The element whose attribute list holds the item; unused for the synthesized item.</summary>
        public int Element;

        /// <summary>The attribute ordinal within that element; unused for the synthesized item.</summary>
        public int Ordinal;
    }


    /// <summary>
    /// Orders <see cref="AttributeRenderItem"/>s by <see cref="CompareAttributeItems"/> for the
    /// introspective sort of <see cref="SortAttributeItems"/>.
    /// </summary>
    private readonly struct AttributeRenderItemComparer: IComparer<AttributeRenderItem>
    {
        /// <summary>The table the items reference attributes of.</summary>
        private XmlNodeTable Table { get; }


        /// <summary>
        /// Creates the comparer over the table the items reference.
        /// </summary>
        /// <param name="table">The table the items reference attributes of.</param>
        public AttributeRenderItemComparer(XmlNodeTable table)
        {
            Table = table;
        }


        /// <inheritdoc />
        public int Compare(AttributeRenderItem left, AttributeRenderItem right)
        {
            return CompareAttributeItems(Table, left, right);
        }
    }


    /// <summary>
    /// The namespace bindings in scope at the node the render walk is visiting, maintained incrementally:
    /// descending into an element pushes its namespace declarations, ascending pops them back to the
    /// element's mark. One slot exists per prefix with an in-scope binding, held sorted lexicographically
    /// by prefix so the namespace axis of section 2.3 iterates in rendering order with the default
    /// namespace first, and each slot chains its bindings innermost first, so the resolution of a prefix
    /// at the visited element is the chain head and the resolution at an ancestor is the nearest chain
    /// entry declared at or above it. A slot retires when its binding chain empties on ascent — it leaves
    /// the sorted iteration and its storage is reused for the next new prefix — so an element's namespace
    /// axis iterates exactly the prefixes in scope at that element, never prefixes declared only on
    /// already-closed parts of the document. The declaration of the <c>xml</c> prefix is omitted under the
    /// condition the section 2.3 namespace-axis rule of the canonicalization specifications states: "omit
    /// namespace node with local name <c>xml</c>, which defines the <c>xml</c> prefix, if its string
    /// value is <c>http://www.w3.org/XML/1998/namespace</c>".
    /// </summary>
    private sealed class NamespaceRenderContext: IDisposable
    {
        /// <summary>The table the walk renders.</summary>
        private XmlNodeTable Table { get; }

        /// <summary>One slot per prefix with an in-scope binding; retired slot storage is reused through <see cref="FreeSlotIndices"/>.</summary>
        private PooledStructList<NamespacePrefixSlot> Slots { get; }

        /// <summary>Slot indices sorted lexicographically by prefix, the default namespace first.</summary>
        private PooledStructList<int> SortedSlotIndices { get; }

        /// <summary>The binding stack; each entry chains to the shadowed binding of its slot.</summary>
        private PooledStructList<NamespaceBindingEntry> BindingStack { get; }

        /// <summary>The storage indices of retired slots, reused before <see cref="Slots"/> grows.</summary>
        private PooledStructList<int> FreeSlotIndices { get; }


        /// <summary>The slot of the default namespace prefix, or -1 while none is in scope.</summary>
        public int DefaultSlotIndex { get; private set; } = -1;

        /// <summary>
        /// The number of slots the prefix-sorted iteration covers; every counted slot holds an in-scope
        /// binding, because a slot retires when its binding chain empties.
        /// </summary>
        public int SlotCount => SortedSlotIndices.Count;


        /// <summary>
        /// Creates the context with buffers rented from the pool.
        /// </summary>
        /// <param name="table">The table the walk renders.</param>
        /// <param name="pool">The pool every buffer is rented from.</param>
        public NamespaceRenderContext(XmlNodeTable table, MemoryPool<byte> pool)
        {
            Table = table;
            Slots = new PooledStructList<NamespacePrefixSlot>(pool, 8);
            SortedSlotIndices = new PooledStructList<int>(pool, 8);
            BindingStack = new PooledStructList<NamespaceBindingEntry>(pool, 8);
            FreeSlotIndices = new PooledStructList<int>(pool, 8);
        }


        /// <summary>
        /// Pushes the namespace declarations of an element the walk descends into.
        /// </summary>
        /// <param name="elementIndex">The element descended into.</param>
        /// <returns>The mark <see cref="PopScope"/> unwinds to when the walk ascends past the element.</returns>
        public int PushScope(int elementIndex)
        {
            int mark = BindingStack.Count;
            int declarationCount = Table.NamespaceDeclarationCountOf(elementIndex);
            for(int i = 0; i < declarationCount; ++i)
            {
                ReadOnlySpan<byte> prefix = Table.NamespaceDeclarationPrefixOf(elementIndex, i);
                if(prefix.SequenceEqual(XmlCharacters.XmlPrefix) && Table.NamespaceDeclarationUriOf(elementIndex, i).SequenceEqual(XmlCharacters.XmlNamespaceUri))
                {
                    continue;
                }

                int slotIndex = FindOrAddSlot(prefix, elementIndex, i);
                int previousBinding = Slots[slotIndex].HeadBinding;
                int bindingIndex = BindingStack.Add(new NamespaceBindingEntry { SlotIndex = slotIndex, Element = elementIndex, Ordinal = i, PreviousBinding = previousBinding });
                Slots[slotIndex].HeadBinding = bindingIndex;
            }

            return mark;
        }


        /// <summary>
        /// Pops the bindings pushed above a mark, restoring each slot's shadowed binding and retiring
        /// every slot whose binding chain empties, so the prefix-sorted iteration covers only in-scope
        /// prefixes.
        /// </summary>
        /// <param name="mark">The mark returned by the matching <see cref="PushScope"/>.</param>
        public void PopScope(int mark)
        {
            for(int i = BindingStack.Count - 1; i >= mark; --i)
            {
                NamespaceBindingEntry entry = BindingStack[i];
                Slots[entry.SlotIndex].HeadBinding = entry.PreviousBinding;
                if(entry.PreviousBinding < 0)
                {
                    RetireSlot(entry.SlotIndex);
                }
            }

            BindingStack.Truncate(mark);
        }


        /// <summary>
        /// The slot index at a position of the prefix-sorted iteration.
        /// </summary>
        /// <param name="sortedPosition">The position, less than <see cref="SlotCount"/>.</param>
        /// <returns>The slot index.</returns>
        public int SlotIndexAt(int sortedPosition)
        {
            return SortedSlotIndices[sortedPosition];
        }


        /// <summary>
        /// The innermost in-scope binding of a slot — the resolution of the slot's prefix at the visited
        /// element.
        /// </summary>
        /// <param name="slotIndex">The slot, or -1 for a prefix without a slot.</param>
        /// <param name="declarationElement">The element whose declaration list holds the binding.</param>
        /// <param name="declarationOrdinal">The declaration ordinal within that element.</param>
        /// <returns><see langword="true"/> when a binding is in scope.</returns>
        public bool TryGetInScopeBinding(int slotIndex, out int declarationElement, out int declarationOrdinal)
        {
            if(slotIndex >= 0 && Slots[slotIndex].HeadBinding >= 0)
            {
                NamespaceBindingEntry entry = BindingStack[Slots[slotIndex].HeadBinding];
                declarationElement = entry.Element;
                declarationOrdinal = entry.Ordinal;

                return true;
            }

            declarationElement = -1;
            declarationOrdinal = -1;

            return false;
        }


        /// <summary>
        /// The binding of a slot in effect at an ancestor of the visited element: the innermost chain
        /// entry whose declaring element is the ancestor or above it. The declaring elements on a chain
        /// all lie on the walked root-to-element path, where an ancestor always has the smaller node
        /// index, so the comparison over node indices decides the ancestry exactly.
        /// </summary>
        /// <param name="slotIndex">The slot, or -1 for a prefix without a slot.</param>
        /// <param name="ancestorElementIndex">The ancestor element on the walked path, or -1 for none.</param>
        /// <param name="declarationElement">The element whose declaration list holds the binding.</param>
        /// <param name="declarationOrdinal">The declaration ordinal within that element.</param>
        /// <returns><see langword="true"/> when a binding is in effect at the ancestor.</returns>
        public bool TryGetBindingAt(int slotIndex, int ancestorElementIndex, out int declarationElement, out int declarationOrdinal)
        {
            if(slotIndex >= 0)
            {
                for(int binding = Slots[slotIndex].HeadBinding; binding >= 0; binding = BindingStack[binding].PreviousBinding)
                {
                    NamespaceBindingEntry entry = BindingStack[binding];
                    if(entry.Element <= ancestorElementIndex)
                    {
                        declarationElement = entry.Element;
                        declarationOrdinal = entry.Ordinal;

                        return true;
                    }
                }
            }

            declarationElement = -1;
            declarationOrdinal = -1;

            return false;
        }


        /// <summary>
        /// Returns every pooled buffer the context holds.
        /// </summary>
        public void Dispose()
        {
            Slots.Dispose();
            SortedSlotIndices.Dispose();
            BindingStack.Dispose();
            FreeSlotIndices.Dispose();
        }


        /// <summary>
        /// Finds the slot of a prefix by binary search over the sorted slot indices, creating and
        /// sort-inserting one on the prefix's first in-scope occurrence, reusing retired slot storage
        /// before growing.
        /// </summary>
        /// <param name="prefix">The declared prefix; empty for the default namespace.</param>
        /// <param name="declarationElement">The element whose declaration carries the prefix octets.</param>
        /// <param name="declarationOrdinal">The declaration ordinal within that element.</param>
        /// <returns>The slot index.</returns>
        private int FindOrAddSlot(ReadOnlySpan<byte> prefix, int declarationElement, int declarationOrdinal)
        {
            if(TryFindSortedPosition(prefix, out int position))
            {
                return SortedSlotIndices[position];
            }

            var slot = new NamespacePrefixSlot { PrefixElement = declarationElement, PrefixOrdinal = declarationOrdinal, HeadBinding = -1 };
            int slotIndex;
            if(FreeSlotIndices.Count > 0)
            {
                slotIndex = FreeSlotIndices[FreeSlotIndices.Count - 1];
                FreeSlotIndices.Truncate(FreeSlotIndices.Count - 1);
                Slots[slotIndex] = slot;
            }
            else
            {
                slotIndex = Slots.Add(slot);
            }

            SortedSlotIndices.Insert(position, slotIndex);
            if(prefix.IsEmpty)
            {
                DefaultSlotIndex = slotIndex;
            }

            return slotIndex;
        }


        /// <summary>
        /// Retires a slot whose binding chain has emptied: the slot leaves the prefix-sorted iteration,
        /// its storage joins the free list, and the default-namespace designation clears when the slot
        /// carried it.
        /// </summary>
        /// <param name="slotIndex">The slot with an empty binding chain.</param>
        private void RetireSlot(int slotIndex)
        {
            NamespacePrefixSlot slot = Slots[slotIndex];
            _ = TryFindSortedPosition(Table.NamespaceDeclarationPrefixOf(slot.PrefixElement, slot.PrefixOrdinal), out int position);
            SortedSlotIndices.RemoveAt(position);
            FreeSlotIndices.Add(slotIndex);
            if(slotIndex == DefaultSlotIndex)
            {
                DefaultSlotIndex = -1;
            }
        }


        /// <summary>
        /// Locates a prefix in the sorted slot indices by binary search: the position of its slot when
        /// one is in scope, the insertion position that keeps the ordering otherwise.
        /// </summary>
        /// <param name="prefix">The prefix; empty for the default namespace.</param>
        /// <param name="position">The found position, or the insertion position.</param>
        /// <returns><see langword="true"/> when a slot for the prefix is in the sorted iteration.</returns>
        private bool TryFindSortedPosition(ReadOnlySpan<byte> prefix, out int position)
        {
            int low = 0;
            int high = SortedSlotIndices.Count - 1;
            while(low <= high)
            {
                int middle = (low + high) >> 1;
                NamespacePrefixSlot slot = Slots[SortedSlotIndices[middle]];
                int comparison = Table.NamespaceDeclarationPrefixOf(slot.PrefixElement, slot.PrefixOrdinal).SequenceCompareTo(prefix);
                if(comparison == 0)
                {
                    position = middle;

                    return true;
                }

                if(comparison < 0)
                {
                    low = middle + 1;
                }
                else
                {
                    high = middle - 1;
                }
            }

            position = low;

            return false;
        }
    }


    /// <summary>
    /// Renders the node-set into canonical octets appended to the output list.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="nodeSet">The node-set to render.</param>
    /// <param name="variant">The algorithm family.</param>
    /// <param name="isWithComments">Whether comment nodes render; a comment renders only when this is
    /// <see langword="true"/> AND <paramref name="nodeSet"/> does not carry the
    /// <see cref="XmlNodeSet.WithoutComments"/> mark.</param>
    /// <param name="inclusivePrefixes">The <c>InclusiveNamespaces PrefixList</c> tokens the
    /// <see cref="XmlCanonicalVariant.Exclusive10"/> family honors; ignored by the inclusive families.</param>
    /// <param name="pool">The pool every scratch buffer is rented from.</param>
    /// <param name="output">The list the canonical octets are appended to.</param>
    public static void Render(XmlNodeTable table, in XmlNodeSet nodeSet, XmlCanonicalVariant variant, bool isWithComments, ExclusivePrefixSet inclusivePrefixes, MemoryPool<byte> pool, PooledStructList<byte> output)
    {
        int documentElement = table.DocumentElementIndex;
        using var namespaceContext = new NamespaceRenderContext(table, pool);
        using var stack = new PooledStructList<RenderFrame>(pool, 32);
        stack.Add(new RenderFrame
        {
            NodeIndex = table.RootIndex,
            NextChild = table.FirstChildOf(table.RootIndex),
            IsRendered = false,
            IsNodeInSet = nodeSet.IsWholeDocument,
            IsUnderApex = false,
            NearestInSetElement = -1,
            NamespaceScopeMark = 0
        });
        while(stack.Count > 0)
        {
            ref RenderFrame frame = ref stack[stack.Count - 1];
            if(frame.NextChild < 0)
            {
                if(frame.IsRendered)
                {
                    output.AddRange("</"u8);
                    AppendQName(table, frame.NodeIndex, output);
                    output.Add((byte)'>');
                }

                namespaceContext.PopScope(frame.NamespaceScopeMark);
                stack.Truncate(stack.Count - 1);

                continue;
            }

            int child = frame.NextChild;
            frame.NextChild = table.NextSiblingOf(child);
            bool isContentInSet = nodeSet.IsWholeDocument || frame.IsUnderApex;
            _ = table.KindOf(child) switch
            {
                XmlNodeKind.Element => RenderElementChild(table, in nodeSet, variant, inclusivePrefixes, child, namespaceContext, stack, pool, output),
                XmlNodeKind.Text => isContentInSet && RenderTextChild(table, child, output),
                XmlNodeKind.Comment => isWithComments && !nodeSet.ExcludesComments && isContentInSet && RenderCommentOrProcessingInstruction(table, child, documentElement, isComment: true, output),
                XmlNodeKind.ProcessingInstruction => isContentInSet && RenderCommentOrProcessingInstruction(table, child, documentElement, isComment: false, output),
                _ => false
            };
        }
    }


    /// <summary>
    /// Processes one element child of the render walk: an excluded subtree apex contributes nothing;
    /// otherwise the element's namespace scope pushes onto the context, its start tag renders when the
    /// element is in the set, and a frame descends into its children either way, because an omitted
    /// element's descendants may still be in the set under the document-subsets processing of
    /// section 2.4. The walk never descends into an excluded subtree, so every ancestor of the child has
    /// already been decided non-excluded and the exclusion test is membership over the exclusion apexes
    /// alone; set membership likewise reads from the parent frame instead of the ancestor axis.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="nodeSet">The node-set.</param>
    /// <param name="variant">The algorithm family.</param>
    /// <param name="inclusivePrefixes">The <c>InclusiveNamespaces PrefixList</c> tokens the exclusive
    /// family honors.</param>
    /// <param name="elementIndex">The element child.</param>
    /// <param name="namespaceContext">The in-scope namespace bindings of the walk.</param>
    /// <param name="stack">The walk stack the descent frame is pushed onto.</param>
    /// <param name="pool">The pool scratch buffers are rented from.</param>
    /// <param name="output">The list the octets are appended to.</param>
    /// <returns><see langword="true"/> when the element's start tag rendered.</returns>
    private static bool RenderElementChild(XmlNodeTable table, in XmlNodeSet nodeSet, XmlCanonicalVariant variant, ExclusivePrefixSet inclusivePrefixes, int elementIndex, NamespaceRenderContext namespaceContext, PooledStructList<RenderFrame> stack, MemoryPool<byte> pool, PooledStructList<byte> output)
    {
        if(IsExcludedSubtreeApex(in nodeSet, elementIndex))
        {
            return false;
        }

        RenderFrame parentFrame = stack[stack.Count - 1];
        bool isUnderApex = elementIndex == nodeSet.ApexElementIndex || parentFrame.IsUnderApex;
        bool isRendered = nodeSet.IsWholeDocument || isUnderApex || IsAncestorContextElement(in nodeSet, elementIndex);
        int namespaceScopeMark = namespaceContext.PushScope(elementIndex);
        if(isRendered)
        {
            RenderStartTag(table, variant, inclusivePrefixes, elementIndex, parentFrame.NearestInSetElement, parentFrame.IsNodeInSet, namespaceContext, stack, pool, output);
        }

        stack.Add(new RenderFrame
        {
            NodeIndex = elementIndex,
            NextChild = table.FirstChildOf(elementIndex),
            IsRendered = isRendered,
            IsNodeInSet = isRendered,
            IsUnderApex = isUnderApex,
            NearestInSetElement = isRendered ? elementIndex : parentFrame.NearestInSetElement,
            NamespaceScopeMark = namespaceScopeMark
        });

        return isRendered;
    }


    /// <summary>
    /// Tells whether an element is the apex of an excluded subtree of the set.
    /// </summary>
    /// <param name="nodeSet">The node-set.</param>
    /// <param name="elementIndex">The element to test.</param>
    /// <returns><see langword="true"/> when the element is an exclusion apex.</returns>
    private static bool IsExcludedSubtreeApex(in XmlNodeSet nodeSet, int elementIndex)
    {
        for(int i = 0; i < nodeSet.ExclusionCount; ++i)
        {
            if(nodeSet.ExclusionAt(i) == elementIndex)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Tells whether an element is one of the set's ancestor-context elements.
    /// </summary>
    /// <param name="nodeSet">The node-set.</param>
    /// <param name="elementIndex">The element to test.</param>
    /// <returns><see langword="true"/> when the element is ancestor context.</returns>
    private static bool IsAncestorContextElement(in XmlNodeSet nodeSet, int elementIndex)
    {
        for(int i = 0; i < nodeSet.AncestorContextCount; ++i)
        {
            if(nodeSet.AncestorContextAt(i) == elementIndex)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Renders one text child of the walk with the section 2.3 text escaping of
    /// <see cref="AppendEscapedText"/>; membership in the set is decided at the call site from the parent
    /// frame.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="nodeIndex">The text child.</param>
    /// <param name="output">The list the octets are appended to.</param>
    /// <returns><see langword="true"/> always: the text renders unconditionally once membership is decided.</returns>
    private static bool RenderTextChild(XmlNodeTable table, int nodeIndex, PooledStructList<byte> output)
    {
        AppendEscapedText(table.ValueOf(nodeIndex), output);

        return true;
    }


    /// <summary>
    /// Renders the start tag of an element in the set: the open angle bracket, the QName with the prefix
    /// from the input document, the namespace axis, the attribute axis and the close angle bracket, per
    /// section 2.3 of the canonicalization specifications.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="variant">The algorithm family.</param>
    /// <param name="inclusivePrefixes">The <c>InclusiveNamespaces PrefixList</c> tokens the exclusive
    /// family honors.</param>
    /// <param name="elementIndex">The element to render.</param>
    /// <param name="nearestInSetAncestor">The nearest ancestor element in the set, or -1.</param>
    /// <param name="isParentInSet">Whether the element's parent node is in the set.</param>
    /// <param name="namespaceContext">The in-scope namespace bindings of the walk.</param>
    /// <param name="stack">The walk stack, whose frames above the root are the element's ancestors.</param>
    /// <param name="pool">The pool scratch buffers are rented from.</param>
    /// <param name="output">The list the octets are appended to.</param>
    private static void RenderStartTag(XmlNodeTable table, XmlCanonicalVariant variant, ExclusivePrefixSet inclusivePrefixes, int elementIndex, int nearestInSetAncestor, bool isParentInSet, NamespaceRenderContext namespaceContext, PooledStructList<RenderFrame> stack, MemoryPool<byte> pool, PooledStructList<byte> output)
    {
        output.Add((byte)'<');
        AppendQName(table, elementIndex, output);
        if(variant == XmlCanonicalVariant.Exclusive10)
        {
            RenderNamespaceAxisExclusive(table, elementIndex, inclusivePrefixes, nearestInSetAncestor, namespaceContext, stack, output);
        }
        else
        {
            RenderNamespaceAxis(table, elementIndex, nearestInSetAncestor, namespaceContext, output);
        }

        RenderAttributeAxis(table, variant, elementIndex, isParentInSet, stack, pool, output);
        output.Add((byte)'>');
    }


    /// <summary>
    /// Renders the namespace axis of an element per section 2.3: the in-scope bindings sorted
    /// lexicographically by prefix with the default namespace first, the declaration of the <c>xml</c>
    /// prefix for its defined namespace name omitted, bindings equal to the nearest rendered ancestor's
    /// suppressed as superfluous, and <c>xmlns=""</c> emitted exactly when the element has no default
    /// namespace node while its nearest in-set ancestor has one.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The element whose axis renders.</param>
    /// <param name="nearestInSetAncestor">The nearest ancestor element in the set, or -1.</param>
    /// <param name="namespaceContext">The in-scope namespace bindings of the walk.</param>
    /// <param name="output">The list the octets are appended to.</param>
    private static void RenderNamespaceAxis(XmlNodeTable table, int elementIndex, int nearestInSetAncestor, NamespaceRenderContext namespaceContext, PooledStructList<byte> output)
    {
        bool hasOwnDefault = namespaceContext.TryGetInScopeBinding(namespaceContext.DefaultSlotIndex, out int ownDefaultElement, out int ownDefaultOrdinal)
            && table.NamespaceDeclarationUriOf(ownDefaultElement, ownDefaultOrdinal).Length > 0;
        bool ancestorHasDefault = namespaceContext.TryGetBindingAt(namespaceContext.DefaultSlotIndex, nearestInSetAncestor, out int ancestorDefaultElement, out int ancestorDefaultOrdinal)
            && table.NamespaceDeclarationUriOf(ancestorDefaultElement, ancestorDefaultOrdinal).Length > 0;
        if(!hasOwnDefault && ancestorHasDefault)
        {
            output.AddRange(" xmlns=\"\""u8);
        }

        for(int i = 0; i < namespaceContext.SlotCount; ++i)
        {
            int slotIndex = namespaceContext.SlotIndexAt(i);
            if(!namespaceContext.TryGetInScopeBinding(slotIndex, out int bindingElement, out int bindingOrdinal))
            {
                continue;
            }

            ReadOnlySpan<byte> uri = table.NamespaceDeclarationUriOf(bindingElement, bindingOrdinal);
            if(uri.IsEmpty)
            {
                continue;
            }

            bool isSuppressed = namespaceContext.TryGetBindingAt(slotIndex, nearestInSetAncestor, out int ancestorElement, out int ancestorOrdinal)
                && ((ancestorElement == bindingElement && ancestorOrdinal == bindingOrdinal)
                    || table.NamespaceDeclarationUriOf(ancestorElement, ancestorOrdinal).SequenceEqual(uri));
            if(isSuppressed)
            {
                continue;
            }

            AppendNamespaceDeclaration(table.NamespaceDeclarationPrefixOf(bindingElement, bindingOrdinal), uri, output);
        }
    }


    /// <summary>
    /// Renders the namespace axis of an element per section 3 of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see>: a namespace node whose prefix is not on the <c>InclusiveNamespaces PrefixList</c>
    /// renders exactly when "it is visibly utilized by its parent element" and "the prefix has not yet
    /// been rendered by any output ancestor, or the nearest output ancestor of its parent element that
    /// visibly utilizes the namespace prefix does not have a namespace node in the node-set with the same
    /// namespace prefix and value" (item 3); a listed prefix and, with the <c>#default</c> token listed,
    /// the default namespace are "handled as provided in Canonical XML" (item 2); and without the
    /// <c>#default</c> token <c>xmlns=""</c> is output exactly when the element "visibly utilizes the
    /// default namespace", "has no default namespace node in the node-set", and "the nearest output
    /// ancestor of E that visibly utilizes the default namespace has a default namespace node in the
    /// node-set" (item 4).
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The element whose axis renders.</param>
    /// <param name="inclusivePrefixes">The <c>InclusiveNamespaces PrefixList</c> tokens.</param>
    /// <param name="nearestInSetAncestor">The nearest ancestor element in the set, or -1.</param>
    /// <param name="namespaceContext">The in-scope namespace bindings of the walk.</param>
    /// <param name="stack">The walk stack, whose frames above the root are the element's ancestors.</param>
    /// <param name="output">The list the octets are appended to.</param>
    private static void RenderNamespaceAxisExclusive(XmlNodeTable table, int elementIndex, ExclusivePrefixSet inclusivePrefixes, int nearestInSetAncestor, NamespaceRenderContext namespaceContext, PooledStructList<RenderFrame> stack, PooledStructList<byte> output)
    {
        bool isElementUnprefixed = table.PrefixOf(elementIndex).IsEmpty;
        bool hasOwnDefault = namespaceContext.TryGetInScopeBinding(namespaceContext.DefaultSlotIndex, out int ownDefaultElement, out int ownDefaultOrdinal)
            && table.NamespaceDeclarationUriOf(ownDefaultElement, ownDefaultOrdinal).Length > 0;
        bool isEmptyDefaultRendered;
        if(inclusivePrefixes.HasDefaultToken)
        {
            bool ancestorHasDefault = namespaceContext.TryGetBindingAt(namespaceContext.DefaultSlotIndex, nearestInSetAncestor, out int ancestorDefaultElement, out int ancestorDefaultOrdinal)
                && table.NamespaceDeclarationUriOf(ancestorDefaultElement, ancestorDefaultOrdinal).Length > 0;
            isEmptyDefaultRendered = !hasOwnDefault && ancestorHasDefault;
        }
        else
        {
            int utilizingAncestor = NearestInSetAncestorVisiblyUtilizing(table, stack, default);
            bool utilizingAncestorHasDefault = namespaceContext.TryGetBindingAt(namespaceContext.DefaultSlotIndex, utilizingAncestor, out int utilizingDefaultElement, out int utilizingDefaultOrdinal)
                && table.NamespaceDeclarationUriOf(utilizingDefaultElement, utilizingDefaultOrdinal).Length > 0;
            isEmptyDefaultRendered = isElementUnprefixed && !hasOwnDefault && utilizingAncestorHasDefault;
        }

        if(isEmptyDefaultRendered)
        {
            output.AddRange(" xmlns=\"\""u8);
        }

        for(int i = 0; i < namespaceContext.SlotCount; ++i)
        {
            int slotIndex = namespaceContext.SlotIndexAt(i);
            if(!namespaceContext.TryGetInScopeBinding(slotIndex, out int bindingElement, out int bindingOrdinal))
            {
                continue;
            }

            ReadOnlySpan<byte> uri = table.NamespaceDeclarationUriOf(bindingElement, bindingOrdinal);
            if(uri.IsEmpty)
            {
                continue;
            }

            ReadOnlySpan<byte> prefix = table.NamespaceDeclarationPrefixOf(bindingElement, bindingOrdinal);
            if(IsExclusiveNamespaceRendered(table, slotIndex, prefix, uri, inclusivePrefixes, isElementUnprefixed, nearestInSetAncestor, elementIndex, namespaceContext, stack))
            {
                AppendNamespaceDeclaration(prefix, uri, output);
            }
        }
    }


    /// <summary>
    /// Decides whether one in-scope namespace binding of an element renders under the exclusive policy: a
    /// listed prefix by the Canonical XML superfluous-declaration rule against the nearest in-set ancestor
    /// (section 3 item 2 of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see>), an unlisted one by the visibly-utilizes conditions of section 3 items 3 and 4.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="slotIndex">The context slot of the binding's prefix.</param>
    /// <param name="prefix">The binding's prefix; empty for the default namespace.</param>
    /// <param name="uri">The binding's namespace name.</param>
    /// <param name="inclusivePrefixes">The <c>InclusiveNamespaces PrefixList</c> tokens.</param>
    /// <param name="isElementUnprefixed">Whether the element's own name carries no prefix.</param>
    /// <param name="nearestInSetAncestor">The nearest ancestor element in the set, or -1.</param>
    /// <param name="elementIndex">The element whose axis is rendering.</param>
    /// <param name="namespaceContext">The in-scope namespace bindings of the walk.</param>
    /// <param name="stack">The walk stack, whose frames above the root are the element's ancestors.</param>
    /// <returns><see langword="true"/> when the binding renders.</returns>
    private static bool IsExclusiveNamespaceRendered(XmlNodeTable table, int slotIndex, ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> uri, ExclusivePrefixSet inclusivePrefixes, bool isElementUnprefixed, int nearestInSetAncestor, int elementIndex, NamespaceRenderContext namespaceContext, PooledStructList<RenderFrame> stack)
    {
        bool isListed = prefix.IsEmpty ? inclusivePrefixes.HasDefaultToken : inclusivePrefixes.Contains(prefix);
        if(isListed)
        {
            bool isSuperfluous = namespaceContext.TryGetBindingAt(slotIndex, nearestInSetAncestor, out int ancestorElement, out int ancestorOrdinal)
                && table.NamespaceDeclarationUriOf(ancestorElement, ancestorOrdinal).SequenceEqual(uri);

            return !isSuperfluous;
        }

        bool isVisiblyUtilized = prefix.IsEmpty ? isElementUnprefixed : VisiblyUtilizesPrefix(table, elementIndex, prefix);
        if(!isVisiblyUtilized)
        {
            return false;
        }

        int utilizingAncestor = NearestInSetAncestorVisiblyUtilizing(table, stack, prefix);
        if(utilizingAncestor < 0)
        {
            return true;
        }

        bool isInEffect = namespaceContext.TryGetBindingAt(slotIndex, utilizingAncestor, out int effectiveElement, out int effectiveOrdinal)
            && table.NamespaceDeclarationUriOf(effectiveElement, effectiveOrdinal).SequenceEqual(uri);

        return !isInEffect;
    }


    /// <summary>
    /// Tells whether an element visibly utilizes a namespace prefix per section 1.1 of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see>: the element "or an attribute node in the document subset with parent E has a qualified
    /// name in which P is the namespace prefix". The appearance of a prefix within an attribute value is
    /// not visible utilization, per section 5 item 3.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The element to test.</param>
    /// <param name="prefix">The non-empty prefix; visible utilization of the default namespace is the
    /// element's own name carrying no prefix and is decided at the call site.</param>
    /// <returns><see langword="true"/> when the element visibly utilizes the prefix.</returns>
    private static bool VisiblyUtilizesPrefix(XmlNodeTable table, int elementIndex, ReadOnlySpan<byte> prefix)
    {
        if(table.PrefixOf(elementIndex).SequenceEqual(prefix))
        {
            return true;
        }

        int attributeCount = table.AttributeCountOf(elementIndex);
        for(int i = 0; i < attributeCount; ++i)
        {
            if(table.AttributePrefixOf(elementIndex, i).SequenceEqual(prefix))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// The nearest output ancestor — ancestor element in the node-set, per the section 1.1 definitions of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> — that visibly utilizes the given namespace prefix, or -1 when none does. The walk stack's
    /// frames above the root are exactly the ancestors of the element whose axis is rendering, each
    /// carrying the node-set membership decided when it was descended into. An empty prefix asks for the
    /// default namespace, which an element visibly utilizes when its own name carries no prefix.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="stack">The walk stack.</param>
    /// <param name="prefix">The prefix to search for; empty for the default namespace.</param>
    /// <returns>The nearest visibly-utilizing output ancestor element index, or -1.</returns>
    private static int NearestInSetAncestorVisiblyUtilizing(XmlNodeTable table, PooledStructList<RenderFrame> stack, ReadOnlySpan<byte> prefix)
    {
        for(int i = stack.Count - 1; i >= 1; --i)
        {
            RenderFrame frame = stack[i];
            if(!frame.IsNodeInSet)
            {
                continue;
            }

            bool isUtilizing = prefix.IsEmpty ? table.PrefixOf(frame.NodeIndex).IsEmpty : VisiblyUtilizesPrefix(table, frame.NodeIndex, prefix);
            if(isUtilizing)
            {
                return frame.NodeIndex;
            }
        }

        return -1;
    }


    /// <summary>
    /// Appends one namespace declaration per section 2.3 of the canonicalization specifications: a
    /// leading space, <c>xmlns</c> with the colon and prefix for a non-default binding, and the
    /// double-quoted namespace name escaped as an attribute value.
    /// </summary>
    /// <param name="prefix">The binding's prefix; empty for the default namespace.</param>
    /// <param name="uri">The binding's namespace name.</param>
    /// <param name="output">The list the octets are appended to.</param>
    private static void AppendNamespaceDeclaration(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> uri, PooledStructList<byte> output)
    {
        output.AddRange(" xmlns"u8);
        if(!prefix.IsEmpty)
        {
            output.Add((byte)':');
            output.AddRange(prefix);
        }

        output.AddRange("=\""u8);
        AppendEscapedAttributeValue(uri, output);
        output.Add((byte)'"');
    }


    /// <summary>
    /// Renders the attribute axis of an element per section 2.3, enhanced per section 2.4 when the
    /// element's parent is omitted from the set: <see cref="XmlCanonicalVariant.Inclusive10"/> imports the
    /// nearest occurrence of every <c>xml</c>-namespace attribute from the ancestor axis that the element
    /// does not carry itself; <see cref="XmlCanonicalVariant.Inclusive11"/> imports only <c>xml:lang</c>
    /// and <c>xml:space</c> and joins the <c>xml:base</c> values of contiguously omitted ancestors with
    /// the element's own into one fixed-up value that replaces it, rendered only when non-empty;
    /// <see cref="XmlCanonicalVariant.Exclusive10"/> imports nothing, because the ancestor search and
    /// copying "are omitted from the Exclusive XML Canonicalization method" per section 3 item 1 of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see>. The merged list renders sorted by namespace URI then local name with the empty URI
    /// least.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="variant">The algorithm family.</param>
    /// <param name="elementIndex">The element whose axis renders.</param>
    /// <param name="isParentInSet">Whether the element's parent node is in the set.</param>
    /// <param name="stack">The walk stack, whose frames above the root are the element's ancestors.</param>
    /// <param name="pool">The pool scratch buffers are rented from.</param>
    /// <param name="output">The list the octets are appended to.</param>
    private static void RenderAttributeAxis(XmlNodeTable table, XmlCanonicalVariant variant, int elementIndex, bool isParentInSet, PooledStructList<RenderFrame> stack, MemoryPool<byte> pool, PooledStructList<byte> output)
    {
        using var items = new PooledStructList<AttributeRenderItem>(pool, 8);
        using var synthesizedXmlBase = new PooledStructList<byte>(pool, 16);
        bool hasSynthesizedXmlBase = false;
        bool isOwnXmlBaseConsumed = !isParentInSet && variant switch
        {
            XmlCanonicalVariant.Inclusive10 => ImportInclusive10AttributeAxis(table, elementIndex, items),
            XmlCanonicalVariant.Inclusive11 => ImportInclusive11AttributeAxis(table, stack, elementIndex, pool, synthesizedXmlBase, items, out hasSynthesizedXmlBase),
            _ => false
        };

        int attributeCount = table.AttributeCountOf(elementIndex);
        for(int i = 0; i < attributeCount; ++i)
        {
            if(isOwnXmlBaseConsumed && IsXmlNamespaceAttribute(table, elementIndex, i, "base"u8))
            {
                continue;
            }

            items.Add(new AttributeRenderItem { Source = OwnAttributeSource, Element = elementIndex, Ordinal = i });
        }

        if(hasSynthesizedXmlBase)
        {
            items.Add(new AttributeRenderItem { Source = SynthesizedXmlBaseSource, Element = -1, Ordinal = -1 });
        }

        SortAttributeItems(table, items);
        for(int i = 0; i < items.Count; ++i)
        {
            AttributeRenderItem item = items[i];
            output.Add((byte)' ');
            if(item.Source == SynthesizedXmlBaseSource)
            {
                output.AddRange("xml:base=\""u8);
                AppendEscapedAttributeValue(synthesizedXmlBase.AsSpan(), output);
                output.Add((byte)'"');

                continue;
            }

            ReadOnlySpan<byte> prefix = table.AttributePrefixOf(item.Element, item.Ordinal);
            if(!prefix.IsEmpty)
            {
                output.AddRange(prefix);
                output.Add((byte)':');
            }

            output.AddRange(table.AttributeLocalNameOf(item.Element, item.Ordinal));
            output.AddRange("=\""u8);
            AppendEscapedAttributeValue(table.AttributeValueOf(item.Element, item.Ordinal), output);
            output.Add((byte)'"');
        }
    }


    /// <summary>
    /// The section 2.4 attribute-axis enhancement of
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> for an element
    /// whose parent is omitted: the nearest occurrence of every <c>xml</c>-namespace attribute imports
    /// from the ancestor axis.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The element receiving the imports.</param>
    /// <param name="items">The render list imports are appended to.</param>
    /// <returns><see langword="false"/>: the import never consumes the element's own <c>xml:base</c>,
    /// which Canonical XML 1.0 renders verbatim.</returns>
    private static bool ImportInclusive10AttributeAxis(XmlNodeTable table, int elementIndex, PooledStructList<AttributeRenderItem> items)
    {
        ImportNearestXmlNamespaceAttributes(table, elementIndex, isSimpleInheritableOnly: false, items);

        return false;
    }


    /// <summary>
    /// The section 2.4 attribute-axis enhancement of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see> for an
    /// element whose parent is omitted: only the simple inheritable <c>xml:lang</c> and <c>xml:space</c>
    /// import, and the <c>xml:base</c> values of contiguously omitted ancestors join with the element's
    /// own through the fixup of <see cref="TryFixupXmlBase"/>.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="stack">The walk stack, whose frames above the root are the element's ancestors.</param>
    /// <param name="elementIndex">The element receiving the imports.</param>
    /// <param name="pool">The pool scratch buffers are rented from.</param>
    /// <param name="synthesizedXmlBase">The list the joined <c>xml:base</c> value is appended to.</param>
    /// <param name="items">The render list imports are appended to.</param>
    /// <param name="hasSynthesizedXmlBase">Whether a non-empty joined value was produced.</param>
    /// <returns><see langword="true"/> when the fixup ran and consumed the element's own <c>xml:base</c>.</returns>
    private static bool ImportInclusive11AttributeAxis(XmlNodeTable table, PooledStructList<RenderFrame> stack, int elementIndex, MemoryPool<byte> pool, PooledStructList<byte> synthesizedXmlBase, PooledStructList<AttributeRenderItem> items, out bool hasSynthesizedXmlBase)
    {
        ImportNearestXmlNamespaceAttributes(table, elementIndex, isSimpleInheritableOnly: true, items);

        return TryFixupXmlBase(table, stack, elementIndex, pool, synthesizedXmlBase, out hasSynthesizedXmlBase);
    }


    /// <summary>
    /// Imports into the render list the nearest occurrence along the ancestor axis of each
    /// <c>xml</c>-namespace attribute the element does not carry itself, per section 2.4: every local name
    /// for <see cref="XmlCanonicalVariant.Inclusive10"/>, only the simple inheritable <c>xml:lang</c> and
    /// <c>xml:space</c> for <see cref="XmlCanonicalVariant.Inclusive11"/>.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The element receiving the imports.</param>
    /// <param name="isSimpleInheritableOnly">Whether only <c>xml:lang</c> and <c>xml:space</c> import.</param>
    /// <param name="items">The render list imports are appended to.</param>
    private static void ImportNearestXmlNamespaceAttributes(XmlNodeTable table, int elementIndex, bool isSimpleInheritableOnly, PooledStructList<AttributeRenderItem> items)
    {
        int importsStart = items.Count;
        for(int ancestor = table.ParentOf(elementIndex); ancestor > 0; ancestor = table.ParentOf(ancestor))
        {
            if(table.KindOf(ancestor) != XmlNodeKind.Element)
            {
                continue;
            }

            int attributeCount = table.AttributeCountOf(ancestor);
            for(int i = 0; i < attributeCount; ++i)
            {
                if(!table.AttributeNamespaceUriOf(ancestor, i).SequenceEqual(XmlCharacters.XmlNamespaceUri))
                {
                    continue;
                }

                ReadOnlySpan<byte> localName = table.AttributeLocalNameOf(ancestor, i);
                if(isSimpleInheritableOnly && !localName.SequenceEqual("lang"u8) && !localName.SequenceEqual("space"u8))
                {
                    continue;
                }

                bool isNearerOccurrenceKnown = false;
                for(int known = importsStart; known < items.Count; ++known)
                {
                    if(table.AttributeLocalNameOf(items[known].Element, items[known].Ordinal).SequenceEqual(localName))
                    {
                        isNearerOccurrenceKnown = true;
                        break;
                    }
                }

                if(isNearerOccurrenceKnown || HasOwnXmlNamespaceAttribute(table, elementIndex, localName))
                {
                    continue;
                }

                items.Add(new AttributeRenderItem { Source = ImportedAttributeSource, Element = ancestor, Ordinal = i });
            }
        }
    }


    /// <summary>
    /// Performs the <c>xml:base</c> fixup of Canonical XML 1.1 section 2.4 for an element whose parent is
    /// omitted: when at least one contiguously omitted ancestor carries <c>xml:base</c>, the values on
    /// those ancestors and on the element itself reduce in reverse document order through
    /// <see cref="XmlBaseUriJoin.Join"/> into one value that replaces the element's own attribute; an
    /// empty result means <c>xml:base</c> is not rendered at all. The contiguously omitted ancestors read
    /// from the walk stack, whose frames above the root are the element's ancestors with their node-set
    /// membership decided at descent.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="stack">The walk stack.</param>
    /// <param name="elementIndex">The element being fixed up.</param>
    /// <param name="pool">The pool scratch buffers are rented from.</param>
    /// <param name="synthesizedXmlBase">The list the joined value is appended to.</param>
    /// <param name="hasSynthesizedXmlBase">Whether a non-empty joined value was produced.</param>
    /// <returns><see langword="true"/> when the fixup ran and consumed the element's own <c>xml:base</c>.</returns>
    /// <remarks>
    /// <strong>Manual disposal, not a <see langword="using"/> declaration.</strong> <c>reduced</c> is
    /// reassigned once per reduction step as each ancestor's value is folded in (a <see langword="using"/>
    /// declaration forbids any reassignment); the <see langword="finally"/> below disposes whichever list it
    /// currently holds on every exit path, and each intermediate <c>joined</c> list is disposed on its own
    /// throw path before <c>reduced</c> is replaced with it.
    /// </remarks>
    private static bool TryFixupXmlBase(XmlNodeTable table, PooledStructList<RenderFrame> stack, int elementIndex, MemoryPool<byte> pool, PooledStructList<byte> synthesizedXmlBase, out bool hasSynthesizedXmlBase)
    {
        hasSynthesizedXmlBase = false;
        using var contiguouslyOmitted = new PooledStructList<int>(pool, 8);
        for(int i = stack.Count - 1; i >= 1; --i)
        {
            RenderFrame frame = stack[i];
            if(frame.IsNodeInSet)
            {
                break;
            }

            contiguouslyOmitted.Add(frame.NodeIndex);
        }

        using var valueSources = new PooledStructList<XmlBaseValueSource>(pool, 8);
        for(int i = contiguouslyOmitted.Count - 1; i >= 0; --i)
        {
            if(TryFindXmlNamespaceAttribute(table, contiguouslyOmitted[i], "base"u8, out int ordinal))
            {
                valueSources.Add(new XmlBaseValueSource { Element = contiguouslyOmitted[i], Ordinal = ordinal });
            }
        }

        if(valueSources.Count == 0)
        {
            return false;
        }

        bool hasOwnValue = TryFindXmlNamespaceAttribute(table, elementIndex, "base"u8, out int ownOrdinal);
        if(hasOwnValue)
        {
            valueSources.Add(new XmlBaseValueSource { Element = elementIndex, Ordinal = ownOrdinal });
        }

        int last = valueSources.Count - 1;
        var reduced = new PooledStructList<byte>(pool, 32);
        try
        {
            reduced.AddRange(table.AttributeValueOf(valueSources[last].Element, valueSources[last].Ordinal));
            for(int i = last - 1; i >= 0; --i)
            {
                var joined = new PooledStructList<byte>(pool, 32);
                try
                {
                    XmlBaseUriJoin.Join(
                        table.AttributeValueOf(valueSources[i].Element, valueSources[i].Ordinal),
                        reduced.AsSpan(),
                        pool,
                        joined);
                }
                catch
                {
                    joined.Dispose();
                    throw;
                }

                reduced.Dispose();
                reduced = joined;
            }

            if(reduced.Count > 0)
            {
                synthesizedXmlBase.AddRange(reduced.AsSpan());
                hasSynthesizedXmlBase = true;
            }
        }
        finally
        {
            reduced.Dispose();
        }

        return true;
    }


    /// <summary>
    /// Tells whether an attribute of an element is in the <c>xml</c> namespace with the given local name.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The element.</param>
    /// <param name="attributeOrdinal">The attribute ordinal.</param>
    /// <param name="localName">The local name to match.</param>
    /// <returns><see langword="true"/> on a match.</returns>
    private static bool IsXmlNamespaceAttribute(XmlNodeTable table, int elementIndex, int attributeOrdinal, ReadOnlySpan<byte> localName)
    {
        return table.AttributeNamespaceUriOf(elementIndex, attributeOrdinal).SequenceEqual(XmlCharacters.XmlNamespaceUri)
            && table.AttributeLocalNameOf(elementIndex, attributeOrdinal).SequenceEqual(localName);
    }


    /// <summary>
    /// Tells whether an element carries an <c>xml</c>-namespace attribute with the given local name.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The element.</param>
    /// <param name="localName">The local name to match.</param>
    /// <returns><see langword="true"/> when the element carries the attribute.</returns>
    private static bool HasOwnXmlNamespaceAttribute(XmlNodeTable table, int elementIndex, ReadOnlySpan<byte> localName)
    {
        return TryFindXmlNamespaceAttribute(table, elementIndex, localName, out _);
    }


    /// <summary>
    /// Finds an <c>xml</c>-namespace attribute of an element by local name.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The element.</param>
    /// <param name="localName">The local name to match.</param>
    /// <param name="attributeOrdinal">The matching attribute ordinal.</param>
    /// <returns><see langword="true"/> when found.</returns>
    private static bool TryFindXmlNamespaceAttribute(XmlNodeTable table, int elementIndex, ReadOnlySpan<byte> localName, out int attributeOrdinal)
    {
        int attributeCount = table.AttributeCountOf(elementIndex);
        for(int i = 0; i < attributeCount; ++i)
        {
            if(IsXmlNamespaceAttribute(table, elementIndex, i, localName))
            {
                attributeOrdinal = i;

                return true;
            }
        }

        attributeOrdinal = -1;

        return false;
    }


    /// <summary>
    /// Sorts the merged attribute render list lexicographically with namespace URI as the primary key and
    /// local name as the secondary key, the empty URI least, per section 2.2 of the canonicalization
    /// specifications: UCS-codepoint order, equivalent to byte order over UTF-8. The introspective sort
    /// runs in O(n log n) comparisons, and its lack of stability cannot reorder equal keys because the
    /// merged list never holds two: expanded attribute names are unique on an element, imports skip local
    /// names the element carries as well as each other, and the synthesized <c>xml:base</c> replaces the
    /// element's own.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="items">The list to sort.</param>
    private static void SortAttributeItems(XmlNodeTable table, PooledStructList<AttributeRenderItem> items)
    {
        items.AsMutableSpan().Sort(new AttributeRenderItemComparer(table));
    }


    /// <summary>
    /// Compares two attribute render items by (namespace URI, local name).
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="left">The left item.</param>
    /// <param name="right">The right item.</param>
    /// <returns>The lexicographic comparison result.</returns>
    private static int CompareAttributeItems(XmlNodeTable table, AttributeRenderItem left, AttributeRenderItem right)
    {
        ReadOnlySpan<byte> leftUri = left.Source == SynthesizedXmlBaseSource ? XmlCharacters.XmlNamespaceUri : table.AttributeNamespaceUriOf(left.Element, left.Ordinal);
        ReadOnlySpan<byte> rightUri = right.Source == SynthesizedXmlBaseSource ? XmlCharacters.XmlNamespaceUri : table.AttributeNamespaceUriOf(right.Element, right.Ordinal);
        int byUri = leftUri.SequenceCompareTo(rightUri);
        if(byUri != 0)
        {
            return byUri;
        }

        ReadOnlySpan<byte> leftLocal = left.Source == SynthesizedXmlBaseSource ? "base"u8 : table.AttributeLocalNameOf(left.Element, left.Ordinal);
        ReadOnlySpan<byte> rightLocal = right.Source == SynthesizedXmlBaseSource ? "base"u8 : table.AttributeLocalNameOf(right.Element, right.Ordinal);

        return leftLocal.SequenceCompareTo(rightLocal);
    }


    /// <summary>
    /// Renders a comment or processing instruction per section 2.3, with the <c>#xA</c> separators the
    /// section places around children of the root node: a trailing <c>#xA</c> before the document element
    /// and a leading <c>#xA</c> after it. Membership in the set is decided at the call site from the
    /// parent frame.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="nodeIndex">The node to render.</param>
    /// <param name="documentElementIndex">The document element index the separator rule compares against.</param>
    /// <param name="isComment">Whether the node renders as a comment.</param>
    /// <param name="output">The list the octets are appended to.</param>
    /// <returns><see langword="true"/> always: the node renders unconditionally once membership is decided.</returns>
    private static bool RenderCommentOrProcessingInstruction(XmlNodeTable table, int nodeIndex, int documentElementIndex, bool isComment, PooledStructList<byte> output)
    {
        bool isRootChild = table.ParentOf(nodeIndex) == table.RootIndex;
        bool isBeforeDocumentElement = nodeIndex < documentElementIndex;
        if(isRootChild && !isBeforeDocumentElement)
        {
            output.Add((byte)0x0A);
        }

        if(isComment)
        {
            output.AddRange("<!--"u8);
            output.AddRange(table.ValueOf(nodeIndex));
            output.AddRange("-->"u8);
        }
        else
        {
            output.AddRange("<?"u8);
            output.AddRange(table.LocalNameOf(nodeIndex));
            ReadOnlySpan<byte> value = table.ValueOf(nodeIndex);
            if(!value.IsEmpty)
            {
                output.Add((byte)' ');
                output.AddRange(value);
            }

            output.AddRange("?>"u8);
        }

        if(isRootChild && isBeforeDocumentElement)
        {
            output.Add((byte)0x0A);
        }

        return true;
    }


    /// <summary>
    /// Appends the QName of an element with the namespace prefix that appeared in the input document, per
    /// section 2.3: the prefix, a colon and the local name, or the local name alone when unprefixed.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The element.</param>
    /// <param name="output">The list the octets are appended to.</param>
    private static void AppendQName(XmlNodeTable table, int elementIndex, PooledStructList<byte> output)
    {
        ReadOnlySpan<byte> prefix = table.PrefixOf(elementIndex);
        if(!prefix.IsEmpty)
        {
            output.AddRange(prefix);
            output.Add((byte)':');
        }

        output.AddRange(table.LocalNameOf(elementIndex));
    }


    /// <summary>
    /// Appends a text node value with the section 2.3 replacements: <c>&amp;</c> to <c>&amp;amp;</c>,
    /// <c>&lt;</c> to <c>&amp;lt;</c>, <c>&gt;</c> to <c>&amp;gt;</c> and <c>#xD</c> to <c>&amp;#xD;</c>.
    /// </summary>
    /// <param name="value">The text value octets.</param>
    /// <param name="output">The list the octets are appended to.</param>
    private static void AppendEscapedText(ReadOnlySpan<byte> value, PooledStructList<byte> output)
    {
        foreach(byte octet in value)
        {
            _ = octet switch
            {
                (byte)'&' => output.AddRange("&amp;"u8),
                (byte)'<' => output.AddRange("&lt;"u8),
                (byte)'>' => output.AddRange("&gt;"u8),
                0x0D => output.AddRange("&#xD;"u8),
                _ => output.Add(octet)
            };
        }
    }


    /// <summary>
    /// Appends an attribute value with the section 2.3 replacements: <c>&amp;</c> to <c>&amp;amp;</c>,
    /// <c>&lt;</c> to <c>&amp;lt;</c>, <c>"</c> to <c>&amp;quot;</c>, and <c>#x9</c>, <c>#xA</c> and
    /// <c>#xD</c> to character references in uppercase hexadecimal with no leading zeros.
    /// </summary>
    /// <param name="value">The attribute value octets.</param>
    /// <param name="output">The list the octets are appended to.</param>
    private static void AppendEscapedAttributeValue(ReadOnlySpan<byte> value, PooledStructList<byte> output)
    {
        foreach(byte octet in value)
        {
            _ = octet switch
            {
                (byte)'&' => output.AddRange("&amp;"u8),
                (byte)'<' => output.AddRange("&lt;"u8),
                (byte)'"' => output.AddRange("&quot;"u8),
                0x09 => output.AddRange("&#x9;"u8),
                0x0A => output.AddRange("&#xA;"u8),
                0x0D => output.AddRange("&#xD;"u8),
                _ => output.Add(octet)
            };
        }
    }
}

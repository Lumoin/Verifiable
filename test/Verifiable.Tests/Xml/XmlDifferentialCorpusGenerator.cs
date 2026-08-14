using System.Text;

namespace Verifiable.Tests.Xml;

/// <summary>
/// One document of the differential corpus of <see cref="XmlDifferentialCorpusGenerator"/>: the document
/// text whose UTF-8 octets feed <see cref="Verifiable.Xml.XmlNodeTable.TryParse"/>, whether the document
/// plants the unique apex element the element-subtree differential selects, and the deterministic
/// <c>InclusiveNamespaces PrefixList</c> of
/// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
/// 1.0</see> section 4 the exclusive-with-prefix-list differential feeds both implementations.
/// </summary>
internal sealed class XmlDifferentialCase
{
    /// <summary>The ordinal of the document within the corpus, named in every mismatch report.</summary>
    public int Index { get; }

    /// <summary>The document text; its UTF-8 octets are the library-side input and the same character
    /// sequence is the platform-side input.</summary>
    public string Xml { get; }

    /// <summary>Whether the document contains exactly one element whose local name is
    /// <see cref="XmlDifferentialCorpusGenerator.ApexLocalName"/>.</summary>
    public bool HasApexElement { get; }

    /// <summary>The white-space separated <c>PrefixList</c> tokens, possibly empty.</summary>
    public string InclusivePrefixList { get; }

    /// <summary>The <c>PrefixList</c> tokens the element-subtree differential can drive faithfully
    /// through the platform transform: <see cref="InclusivePrefixList"/> without the <c>#default</c>
    /// token and without prefixes the document element declares, because a node-list input carries no
    /// namespace nodes for bindings whose declarations lie outside the list while the inclusive handling
    /// of a listed prefix operates on the in-scope namespace axis.</summary>
    public string SubtreeInclusivePrefixList { get; }


    /// <summary>
    /// Creates the corpus case from its parts.
    /// </summary>
    /// <param name="index">The ordinal of the document within the corpus.</param>
    /// <param name="xml">The document text.</param>
    /// <param name="hasApexElement">Whether the document plants the unique apex element.</param>
    /// <param name="inclusivePrefixList">The <c>PrefixList</c> tokens, possibly empty.</param>
    /// <param name="subtreeInclusivePrefixList">The subtree-safe <c>PrefixList</c> tokens, possibly
    /// empty.</param>
    public XmlDifferentialCase(int index, string xml, bool hasApexElement, string inclusivePrefixList, string subtreeInclusivePrefixList)
    {
        Index = index;
        Xml = xml;
        HasApexElement = hasApexElement;
        InclusivePrefixList = inclusivePrefixList;
        SubtreeInclusivePrefixList = subtreeInclusivePrefixList;
    }
}


/// <summary>
/// Mints the deterministic in-process corpus the differential oracle of runs over: procedurally generated
/// documents exercising multiple namespaces and prefixes with shadowing and redundant redeclarations,
/// default-namespace churn including <c>xmlns=""</c> resets, attribute orderings whose (namespace URI,
/// local name) document-order sort of <see
/// href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.2 differs
/// from prefix order, character references, CDATA sections, processing instructions and comments inside
/// and outside the document element, <c>xml:lang</c>/<c>xml:space</c>/<c>xml:base</c> attributes,
/// whitespace-significant text, empty elements, deep nesting, and multi-byte UTF-8 content. A fixed <see
/// cref="Seed"/> drives an xorshift64* generator, so every run mints the identical corpus.
/// </summary>
/// <remarks>
/// The corpus stays within the input classes both implementations accept: no DOCTYPE (this library refuses
/// any document type declaration), only absolute namespace URIs (a relative namespace URI is a refusal per
/// Canonical XML 1.0 section 2.1), no prefix undeclaring (Namespaces in XML 1.0 makes <c>xmlns:p=""</c>
/// XML-1.1-only), only the five predefined entity references, and unique attribute local names per element
/// so no expanded-name duplicate arises. Documents that plant the apex element for the element-subtree
/// differential carry no <c>xml:*</c> attributes on the apex ancestors, because the platform transform
/// propagates such attributes onto every element of a node-list input while section 2.4 of Canonical XML
/// 1.0 augments only an element whose parent is omitted from the node-set; that ancestor-import rule is
/// proven against specification text by the subset-divergence fixtures instead. The deep-nesting chain
/// stays at element depth 64, the deepest the platform transforms accept before their hardening limit
/// refuses the document; the depth-1024 limit of <see cref="Verifiable.Xml.XmlNodeTable"/> itself is
/// proven by the adversarial suite.
/// </remarks>
internal sealed class XmlDifferentialCorpusGenerator
{
    /// <summary>The xorshift64* seed every generation starts from, fixed so the corpus is identical on
    /// every run and a mismatch report's document index always names the same document.</summary>
    internal const ulong Seed = 0xC14BADC0FFEE5EED;

    /// <summary>The number of corpus documents.</summary>
    internal const int DocumentCount = 240;

    /// <summary>The local name of the unique element the element-subtree differential selects; the
    /// element-name pool never produces it, so at most one exists per document.</summary>
    internal const string ApexLocalName = "apex";

    private static readonly string[] ElementNames = ["doc", "item", "node", "data", "entry", "list", "value", "meta", "rec", "unit"];
    private static readonly string[] AttributeLocalNames = ["a", "attr", "idx", "key", "order", "refn", "val", "zed"];
    private static readonly string[] NamespacePrefixes = ["pa", "pb", "pc", "pd", "pe"];
    private static readonly string[] AbsoluteNamespaceUris = ["urn:alpha", "urn:beta", "urn:gamma", "http://example.com/one", "http://example.org/two", "urn:omega"];
    private static readonly string[] TextRuns = ["plain text", "  padded  ", "line1\r\nline2", "greater > than", "ä ö å € 漢字 𐍈", "\n\t indent \n"];
    private static readonly string[] CharacterReferences = ["&#x41;", "&#66;", "&#x20AC;", "&#xD;", "&#x9;", "&#xA;", "&#x10348;"];
    private static readonly string[] EntityReferences = ["&amp;", "&lt;", "&gt;", "&apos;", "&quot;"];
    private static readonly string[] CdataRuns = ["a<b&c>d", " ä € ", "plain cdata"];
    private static readonly string[] CommentRuns = ["c1 note", "x - y", "kommentti ä"];
    private static readonly string[] ProcessingInstructionTargets = ["pi1", "proc", "style-x"];
    private static readonly string[] ProcessingInstructionData = ["d=1 e=2", "  spaced  ", "", "data ä €"];
    private static readonly string[] AttributeValueRuns = ["v1", "  padded  ", "quote ' here", "gt > here", "multi\nline", "ä€漢"];
    private static readonly string[] XmlLangValues = ["en", "fi", "de-DE"];
    private static readonly string[] XmlSpaceValues = ["default", "preserve"];
    private static readonly string[] XmlBaseValues = ["http://example.com/base/", "sub/dir/", "../up"];
    private static readonly string[] PrefixListTokens = ["pa", "pb", "pc", "pd", "pe", "zz", "#default"];

    private ulong state;
    private StringBuilder builder = new();
    private readonly List<(string Prefix, string Uri)> scope = [];
    private readonly List<string> rootDeclaredPrefixes = [];
    private bool isApexDocument;
    private int maximumDepth;
    private int remainingElements;


    /// <summary>
    /// Creates the generator with its starting state.
    /// </summary>
    /// <param name="seed">The nonzero xorshift64* state.</param>
    private XmlDifferentialCorpusGenerator(ulong seed)
    {
        state = seed;
    }


    /// <summary>
    /// Mints the whole corpus from <see cref="Seed"/>.
    /// </summary>
    /// <returns>The <see cref="DocumentCount"/> corpus cases in index order.</returns>
    public static IReadOnlyList<XmlDifferentialCase> Generate()
    {
        var generator = new XmlDifferentialCorpusGenerator(Seed);
        var cases = new List<XmlDifferentialCase>(DocumentCount);
        for(int i = 0; i < DocumentCount; ++i)
        {
            cases.Add(generator.GenerateDocument(i));
        }

        return cases;
    }


    /// <summary>
    /// Generates one corpus document. Even indices plant the apex element as the last child of the
    /// document element; index 1 is the deep-nesting chain.
    /// </summary>
    /// <param name="index">The document ordinal.</param>
    /// <returns>The generated case.</returns>
    private XmlDifferentialCase GenerateDocument(int index)
    {
        if(index == 1)
        {
            return GenerateDeepDocument(index);
        }

        builder = new StringBuilder();
        scope.Clear();
        rootDeclaredPrefixes.Clear();
        isApexDocument = index % 2 == 0;
        maximumDepth = 4 + NextBelow(3);
        remainingElements = 12 + NextBelow(20);

        if(NextChance(40))
        {
            builder.Append("<?xml version=\"1.0\"");
            if(NextChance(50))
            {
                builder.Append(" encoding=\"UTF-8\"");
            }

            if(NextChance(25))
            {
                builder.Append(" standalone=\"yes\"");
            }

            builder.Append("?>");
            if(NextChance(70))
            {
                builder.Append('\n');
            }
        }

        int prologCount = NextBelow(3);
        for(int i = 0; i < prologCount; ++i)
        {
            AppendCommentOrProcessingInstruction();
            AppendMiscellaneousSeparator();
        }

        AppendElement(0, forcedLocalName: null);

        int epilogCount = NextBelow(3);
        for(int i = 0; i < epilogCount; ++i)
        {
            AppendMiscellaneousSeparator();
            AppendCommentOrProcessingInstruction();
        }

        string inclusivePrefixList = GeneratePrefixList();

        return new XmlDifferentialCase(index, builder.ToString(), isApexDocument, inclusivePrefixList, SubtreePrefixListOf(inclusivePrefixList));
    }


    /// <summary>
    /// Generates the deep-nesting chain of sixty-four nested elements, the deepest the platform
    /// transforms accept before their hardening limit refuses the document, with a default namespace, a
    /// prefixed namespace and periodic prefixed attributes so the depth interacts with namespace
    /// resolution.
    /// </summary>
    /// <param name="index">The document ordinal.</param>
    /// <returns>The generated case.</returns>
    private static XmlDifferentialCase GenerateDeepDocument(int index)
    {
        var deepBuilder = new StringBuilder();
        deepBuilder.Append("<d0 xmlns=\"urn:deep\" xmlns:pa=\"urn:alpha\">");
        for(int i = 1; i < 64; ++i)
        {
            deepBuilder.Append("<d").Append(i);
            if(i % 7 == 0)
            {
                deepBuilder.Append(" pa:a=\"v\"");
            }

            deepBuilder.Append('>');
        }

        deepBuilder.Append("deep ä");
        for(int i = 63; i >= 1; --i)
        {
            deepBuilder.Append("</d").Append(i).Append('>');
        }

        deepBuilder.Append("</d0>");

        return new XmlDifferentialCase(index, deepBuilder.ToString(), hasApexElement: false, string.Empty, string.Empty);
    }


    /// <summary>
    /// Narrows a <c>PrefixList</c> to the tokens the element-subtree differential can drive faithfully
    /// through the platform transform: the <c>#default</c> token and every prefix the document element
    /// declares are removed, because those bindings reach the apex only through its namespace axis and a
    /// node-list input carries no namespace nodes for declarations outside the list.
    /// </summary>
    /// <param name="inclusivePrefixList">The whole-document token list.</param>
    /// <returns>The subtree-safe token list, possibly empty.</returns>
    private string SubtreePrefixListOf(string inclusivePrefixList)
    {
        string[] tokens = inclusivePrefixList.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var keptTokens = new List<string>();
        foreach(string token in tokens)
        {
            if(!string.Equals(token, "#default", StringComparison.Ordinal) && !rootDeclaredPrefixes.Contains(token))
            {
                keptTokens.Add(token);
            }
        }

        return string.Join(' ', keptTokens);
    }


    /// <summary>
    /// Appends one element with its namespace declarations, attributes and content, tracking the
    /// namespace scope so element and attribute prefixes always resolve.
    /// </summary>
    /// <param name="depth">The element depth, zero for the document element.</param>
    /// <param name="forcedLocalName">The local name to use, or <see langword="null"/> to draw from the
    /// element-name pool.</param>
    private void AppendElement(int depth, string? forcedLocalName)
    {
        --remainingElements;
        int scopeMark = scope.Count;
        var attributeTexts = new List<string>();
        var prefixesDeclaredHere = new HashSet<string>(StringComparer.Ordinal);

        if(NextChance(55))
        {
            int declarationCount = 1 + NextBelow(3);
            for(int i = 0; i < declarationCount; ++i)
            {
                if(NextChance(30))
                {
                    if(prefixesDeclaredHere.Add(string.Empty))
                    {
                        string uri = NextChance(25) ? string.Empty : Pick(AbsoluteNamespaceUris);
                        attributeTexts.Add($"xmlns=\"{uri}\"");
                        scope.Add((string.Empty, uri));
                    }
                }
                else
                {
                    string prefix = Pick(NamespacePrefixes);
                    if(prefixesDeclaredHere.Add(prefix))
                    {
                        string uri = NextChance(35) && TryResolvePrefix(prefix, out string boundUri) && boundUri.Length > 0 ? boundUri : Pick(AbsoluteNamespaceUris);
                        attributeTexts.Add($"xmlns:{prefix}=\"{uri}\"");
                        scope.Add((prefix, uri));
                        if(depth == 0)
                        {
                            rootDeclaredPrefixes.Add(prefix);
                        }
                    }
                }
            }
        }

        var usablePrefixes = new List<string>();
        foreach((string prefix, string _) in scope)
        {
            if(prefix.Length > 0 && !usablePrefixes.Contains(prefix))
            {
                usablePrefixes.Add(prefix);
            }
        }

        string localName = forcedLocalName ?? Pick(ElementNames);
        string elementPrefix = usablePrefixes.Count > 0 && NextChance(40) ? usablePrefixes[NextBelow(usablePrefixes.Count)] : string.Empty;
        string qualifiedName = elementPrefix.Length == 0 ? localName : elementPrefix + ":" + localName;

        var usedAttributeNames = new HashSet<string>(StringComparer.Ordinal);
        int attributeCount = NextBelow(4);
        for(int i = 0; i < attributeCount; ++i)
        {
            string attributeLocal = Pick(AttributeLocalNames);
            if(!usedAttributeNames.Add(attributeLocal))
            {
                continue;
            }

            string attributePrefix = usablePrefixes.Count > 0 && NextChance(35) ? usablePrefixes[NextBelow(usablePrefixes.Count)] : string.Empty;
            string attributeName = attributePrefix.Length == 0 ? attributeLocal : attributePrefix + ":" + attributeLocal;
            attributeTexts.Add($"{attributeName}=\"{GenerateAttributeValue()}\"");
        }

        bool isXmlAttributeAllowed = !(isApexDocument && depth == 0);
        if(isXmlAttributeAllowed && NextChance(18))
        {
            string xmlAttribute = NextBelow(3) switch
            {
                0 => $"xml:lang=\"{Pick(XmlLangValues)}\"",
                1 => $"xml:space=\"{Pick(XmlSpaceValues)}\"",
                _ => $"xml:base=\"{Pick(XmlBaseValues)}\""
            };
            attributeTexts.Add(xmlAttribute);
        }

        Shuffle(attributeTexts);

        builder.Append('<').Append(qualifiedName);
        foreach(string attributeText in attributeTexts)
        {
            builder.Append(NextChance(12) ? "\n   " : " ").Append(attributeText);
        }

        if(NextChance(8))
        {
            builder.Append(' ');
        }

        bool isApexAppendPending = depth == 0 && isApexDocument;
        bool hasChildren = isApexAppendPending || (depth < maximumDepth && NextChance(depth == 0 ? 95 : 70));
        if(!hasChildren)
        {
            if(NextChance(50))
            {
                builder.Append("/>");
            }
            else
            {
                builder.Append("></").Append(qualifiedName).Append('>');
            }

            scope.RemoveRange(scopeMark, scope.Count - scopeMark);

            return;
        }

        builder.Append('>');
        int childCount = NextBelow(4) + (depth == 0 ? 1 : 0);
        for(int i = 0; i < childCount; ++i)
        {
            AppendChildItem(depth);
        }

        if(isApexAppendPending)
        {
            AppendElement(depth + 1, ApexLocalName);
        }

        builder.Append("</").Append(qualifiedName).Append('>');
        scope.RemoveRange(scopeMark, scope.Count - scopeMark);
    }


    /// <summary>
    /// Appends one content item of an element: a child element while budget and depth allow, text
    /// segments, a CDATA section, a comment, a processing instruction, or whitespace-only text.
    /// </summary>
    /// <param name="depth">The depth of the containing element.</param>
    private void AppendChildItem(int depth)
    {
        int selector = NextBelow(100);
        if(selector < 40 && remainingElements > 0 && depth + 1 <= maximumDepth)
        {
            AppendElement(depth + 1, forcedLocalName: null);

            return;
        }

        if(selector < 60)
        {
            int segmentCount = 1 + NextBelow(3);
            for(int i = 0; i < segmentCount; ++i)
            {
                builder.Append(NextTextSegment());
            }

            return;
        }

        if(selector < 70)
        {
            builder.Append("<![CDATA[").Append(Pick(CdataRuns)).Append("]]>");

            return;
        }

        if(selector < 80)
        {
            builder.Append("<!--").Append(Pick(CommentRuns)).Append("-->");

            return;
        }

        if(selector < 88)
        {
            AppendProcessingInstruction();

            return;
        }

        builder.Append("\n  ");
    }


    /// <summary>
    /// Appends a comment or a processing instruction, the two constructs legal both before and after the
    /// document element.
    /// </summary>
    private void AppendCommentOrProcessingInstruction()
    {
        if(NextChance(50))
        {
            builder.Append("<!--").Append(Pick(CommentRuns)).Append("-->");
        }
        else
        {
            AppendProcessingInstruction();
        }
    }


    /// <summary>
    /// Appends a processing instruction, sometimes without data and sometimes with only white space
    /// between the target and the closing symbol so the canonical target-data separator rule is exercised.
    /// </summary>
    private void AppendProcessingInstruction()
    {
        string target = Pick(ProcessingInstructionTargets);
        string data = Pick(ProcessingInstructionData);
        builder.Append("<?").Append(target);
        if(data.Length > 0)
        {
            builder.Append(' ').Append(data);
        }
        else if(NextChance(40))
        {
            builder.Append("  ");
        }

        builder.Append("?>");
    }


    /// <summary>
    /// Appends the white space between prolog or epilog items: nothing, one line feed, or two.
    /// </summary>
    private void AppendMiscellaneousSeparator()
    {
        int selector = NextBelow(3);
        if(selector > 0)
        {
            builder.Append(selector == 1 ? "\n" : "\n\n");
        }
    }


    /// <summary>
    /// Generates an attribute value of one to three segments drawn from literal runs, character
    /// references and predefined entity references.
    /// </summary>
    /// <returns>The attribute value text.</returns>
    private string GenerateAttributeValue()
    {
        var value = new StringBuilder();
        int segmentCount = 1 + NextBelow(3);
        for(int i = 0; i < segmentCount; ++i)
        {
            string segment = NextBelow(3) switch
            {
                0 => Pick(AttributeValueRuns),
                1 => Pick(CharacterReferences),
                _ => Pick(EntityReferences)
            };
            value.Append(segment);
        }

        return value.ToString();
    }


    /// <summary>
    /// Draws one text segment: a literal run, a character reference, or a predefined entity reference.
    /// </summary>
    /// <returns>The text segment.</returns>
    private string NextTextSegment()
    {
        return NextBelow(3) switch
        {
            0 => Pick(TextRuns),
            1 => Pick(CharacterReferences),
            _ => Pick(EntityReferences)
        };
    }


    /// <summary>
    /// Generates the <c>PrefixList</c> of up to three distinct tokens: pool prefixes whether or not the
    /// document declares them, the never-declared <c>zz</c>, and the <c>#default</c> token.
    /// </summary>
    /// <returns>The white-space separated token list, possibly empty.</returns>
    private string GeneratePrefixList()
    {
        int tokenCount = NextBelow(4);
        var tokens = new List<string>();
        for(int i = 0; i < tokenCount; ++i)
        {
            string token = Pick(PrefixListTokens);
            if(!tokens.Contains(token))
            {
                tokens.Add(token);
            }
        }

        return string.Join(' ', tokens);
    }


    /// <summary>
    /// Resolves a prefix against the current scope, nearest declaration first.
    /// </summary>
    /// <param name="prefix">The prefix to resolve.</param>
    /// <param name="uri">The bound namespace URI when resolution succeeds.</param>
    /// <returns><see langword="true"/> when the prefix is bound in scope.</returns>
    private bool TryResolvePrefix(string prefix, out string uri)
    {
        for(int i = scope.Count - 1; i >= 0; --i)
        {
            if(scope[i].Prefix == prefix)
            {
                uri = scope[i].Uri;

                return true;
            }
        }

        uri = string.Empty;

        return false;
    }


    /// <summary>
    /// Shuffles the attribute texts in place so the serialized attribute order diverges from every sort
    /// order the canonical forms impose.
    /// </summary>
    /// <param name="items">The attribute texts.</param>
    private void Shuffle(List<string> items)
    {
        for(int i = items.Count - 1; i > 0; --i)
        {
            int j = NextBelow(i + 1);
            (items[i], items[j]) = (items[j], items[i]);
        }
    }


    /// <summary>
    /// Draws one item from a pool.
    /// </summary>
    /// <param name="items">The pool.</param>
    /// <returns>The drawn item.</returns>
    private string Pick(string[] items)
    {
        return items[NextBelow(items.Length)];
    }


    /// <summary>
    /// Advances the xorshift64* state and scales the draw below the limit.
    /// </summary>
    /// <param name="limitExclusive">The exclusive upper bound.</param>
    /// <returns>The draw in <c>[0, limitExclusive)</c>.</returns>
    private int NextBelow(int limitExclusive)
    {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        ulong scrambled = state * 0x2545F4914F6CDD1D;

        return (int)(scrambled % (ulong)limitExclusive);
    }


    /// <summary>
    /// Draws a biased boolean.
    /// </summary>
    /// <param name="percent">The chance of <see langword="true"/> in percent.</param>
    /// <returns>The draw.</returns>
    private bool NextChance(int percent)
    {
        return NextBelow(100) < percent;
    }
}

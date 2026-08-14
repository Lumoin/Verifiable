using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The <c>NoticeReferenceType</c>/<c>SPUserNoticeType</c> shape of clause 5.2.9.2's <c>SPUserNotice</c>
/// qualifier: an optional <c>NoticeRef</c> (an <c>Organization</c> string and a <c>NoticeNumbers</c> list of
/// <c>xsd:integer</c> values, both mandatory once <c>NoticeRef</c> itself is present) and an optional
/// <c>ExplicitText</c> string.
/// </summary>
/// <remarks>
/// <c>NoticeNumbers</c>' <c>int</c> entries (arbitrary-precision <c>xsd:integer</c>, per the schema's literal
/// element name) are carried as their raw lexical spans, the same posture <see cref="XAdESObjectIdentifier"/>
/// takes for <c>DocumentationReference</c> — this leaf never computes with them, only carries them through, so
/// no numeric-lexical parser is introduced for a value this reader has no use for beyond passthrough. Carries
/// no owned pooled content of its own — every field is a span computed from <see cref="Table"/> — so no
/// <see cref="IDisposable"/> surface is needed.
/// </remarks>
public readonly struct XAdESSPUserNotice: IEquatable<XAdESSPUserNotice>
{
    /// <summary>The table the qualifier's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>SPUserNotice</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>NoticeRef</c> child is present.</summary>
    public bool HasNoticeRef { get; }

    private int OrganizationTextNodeIndex { get; }

    /// <summary>The naming organization; valid when <see cref="HasNoticeRef"/> is <see langword="true"/>.</summary>
    public ReadOnlySpan<byte> Organization => HasNoticeRef && OrganizationTextNodeIndex >= 0 ? Table.ValueOf(OrganizationTextNodeIndex) : ReadOnlySpan<byte>.Empty;

    private IReadOnlyList<int> NoticeNumberTextNodeIndices { get; }

    /// <summary>
    /// How many <c>int</c> entries <c>NoticeNumbers</c> carries; zero is a legal, non-empty-per-schema list
    /// (<c>IntegerListType</c>'s <c>int</c> child is individually <c>minOccurs="0"</c>), meaningful only when
    /// <see cref="HasNoticeRef"/> is <see langword="true"/>.
    /// </summary>
    public int NoticeNumberCount => NoticeNumberTextNodeIndices.Count;

    /// <summary>The raw lexical <c>xsd:integer</c> content of the entry at the given position, in document order.</summary>
    /// <param name="index">The zero-based position, less than <see cref="NoticeNumberCount"/>.</param>
    public ReadOnlySpan<byte> NoticeNumberAt(int index)
    {
        int textNodeIndex = NoticeNumberTextNodeIndices[index];

        return textNodeIndex >= 0 ? Table.ValueOf(textNodeIndex) : ReadOnlySpan<byte>.Empty;
    }

    /// <summary>Whether the optional <c>ExplicitText</c> child is present.</summary>
    public bool HasExplicitText { get; }

    private int ExplicitTextTextNodeIndex { get; }

    /// <summary>The notice text to display; valid when <see cref="HasExplicitText"/> is <see langword="true"/>.</summary>
    public ReadOnlySpan<byte> ExplicitText => HasExplicitText && ExplicitTextTextNodeIndex >= 0 ? Table.ValueOf(ExplicitTextTextNodeIndex) : ReadOnlySpan<byte>.Empty;


    private XAdESSPUserNotice(
        XmlNodeTable table,
        int elementIndex,
        bool hasNoticeRef,
        int organizationTextNodeIndex,
        IReadOnlyList<int> noticeNumberTextNodeIndices,
        bool hasExplicitText,
        int explicitTextTextNodeIndex)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasNoticeRef = hasNoticeRef;
        OrganizationTextNodeIndex = organizationTextNodeIndex;
        NoticeNumberTextNodeIndices = noticeNumberTextNodeIndices;
        HasExplicitText = hasExplicitText;
        ExplicitTextTextNodeIndex = explicitTextTextNodeIndex;
    }


    /// <summary>
    /// Reads an <c>SPUserNotice</c> element: no attributes of its own, then optional <c>NoticeRef</c> and
    /// optional <c>ExplicitText</c>, in that fixed order. Both being absent is a legal, fully empty
    /// <c>SPUserNotice</c> — clause 5.2.9.2 states no floor on this element the way it does for
    /// <c>SignatureProductionPlaceV2</c>/<c>SignerRoleV2</c>.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XAdESSPUserNotice value, out XAdESReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        bool hasNoticeRef = false;
        int organizationTextNodeIndex = -1;
        List<int> noticeNumberTextNodeIndices = [];
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "NoticeRef"u8))
        {
            int noticeRefElementIndex = child;
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, noticeRefElementIndex, 0, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            ElementScanResult noticeRefScan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, noticeRefElementIndex, out int noticeRefChild);
            if(noticeRefScan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsElement(table, noticeRefChild, XAdESIdentifiers.XAdESNamespaceV132Utf8, "Organization"u8))
            {
                error = new XAdESReadError(
                    noticeRefScan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

                return false;
            }

            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, noticeRefChild, 0, out grammarError)
                || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, noticeRefChild, out organizationTextNodeIndex, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            noticeRefScan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, noticeRefChild, out noticeRefChild);
            if(noticeRefScan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsElement(table, noticeRefChild, XAdESIdentifiers.XAdESNamespaceV132Utf8, "NoticeNumbers"u8))
            {
                error = new XAdESReadError(
                    noticeRefScan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

                return false;
            }

            int noticeNumbersElementIndex = noticeRefChild;
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, noticeNumbersElementIndex, 0, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            if(!XmlSignatureModelGrammar.TryReadElementChildren(table, noticeNumbersElementIndex, out List<int> intElements, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            foreach(int intElement in intElements)
            {
                if(!XmlSignatureModelGrammar.IsElement(table, intElement, XAdESIdentifiers.XAdESNamespaceV132Utf8, "int"u8))
                {
                    error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

                    return false;
                }

                if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, intElement, 0, out grammarError)
                    || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, intElement, out int intTextNodeIndex, out grammarError))
                {
                    error = XAdESGrammar.FromGrammarFailure(grammarError);

                    return false;
                }

                noticeNumberTextNodeIndices.Add(intTextNodeIndex);
            }

            noticeRefScan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, noticeNumbersElementIndex, out _);
            if(noticeRefScan != ElementScanResult.EndOfChildren)
            {
                error = new XAdESReadError(
                    noticeRefScan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            hasNoticeRef = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, noticeRefElementIndex, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        bool hasExplicitText = false;
        int explicitTextTextNodeIndex = -1;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ExplicitText"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError)
                || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out explicitTextTextNodeIndex, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            hasExplicitText = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        if(scan == ElementScanResult.Found)
        {
            bool isRepeat = (hasNoticeRef && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "NoticeRef"u8))
                || (hasExplicitText && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ExplicitText"u8));
            error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        value = new XAdESSPUserNotice(table, elementIndex, hasNoticeRef, organizationTextNodeIndex, noticeNumberTextNodeIndices, hasExplicitText, explicitTextTextNodeIndex);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESSPUserNotice other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESSPUserNotice other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESSPUserNotice left, XAdESSPUserNotice right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESSPUserNotice left, XAdESSPUserNotice right) => !left.Equals(right);
}


/// <summary>
/// The shared <c>SPDocSpecification</c> reader clauses 5.2.9.2 (a <c>SigPolicyQualifier</c>'s content) and
/// 5.2.10 (<c>SignaturePolicyStore</c>'s mandatory child) both instantiate: an
/// <c>xades141:SPDocSpecification</c>-namespaced (<see cref="XAdESIdentifiers.XAdESNamespaceV141"/>) element
/// typed <c>xades:ObjectIdentifierType</c> (the <see cref="XAdESIdentifiers.XAdESNamespaceV132"/> type, a
/// cross-namespace type reference clause 5.2.9.2's own schema preamble states), narrowed by its own
/// directional Qualifier rule: OID-identified content requires <c>Qualifier="OIDAsURN"</c>; URI-identified
/// content forbids <c>Qualifier</c> altogether. <c>Qualifier="OIDAsURI"</c> — legal on
/// <c>ObjectIdentifierType</c> in general — is never legal here.
/// </summary>
internal static class XAdESSPDocSpecification
{
    /// <summary>
    /// Reads an already-identified <c>SPDocSpecification</c> element's <c>ObjectIdentifierType</c> content.
    /// The caller has already confirmed the element's own name and namespace, mirroring
    /// <see cref="XAdESObjectIdentifier.TryRead"/>'s own "caller has already recognized it" posture.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>SPDocSpecification</c> element.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.SPDocSpecificationQualifierNotOIDAsURN"/> when <c>Qualifier</c> is present
    /// with a value other than <c>OIDAsURN</c>.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XAdESObjectIdentifier value, out XAdESReadError error)
    {
        if(!XAdESObjectIdentifier.TryRead(table, elementIndex, out value, out error))
        {
            return false;
        }

        if(value.HasQualifier && value.Qualifier != XAdESObjectIdentifierQualifier.OIDAsURN)
        {
            value = default;
            error = new XAdESReadError(XAdESReadFailure.SPDocSpecificationQualifierNotOIDAsURN, 0);

            return false;
        }

        return true;
    }
}


/// <summary>
/// Which of the three defined signature-policy qualifiers of clause 5.2.9.2 a
/// <see cref="XAdESSigPolicyQualifierEntry"/> recognizes, or <see cref="Unrecognized"/> for genuinely open
/// content the <c>SigPolicyQualifier</c> element's own <c>AnyType</c> content model (clause 5.2.9.1)
/// otherwise permits — never a read refusal: this type recognizes the three defined qualifiers and carries
/// any other content as unmodeled, with no refusal for unknown qualifiers.
/// </summary>
public enum XAdESSigPolicyQualifierKind
{
    /// <summary>Content this reader does not classify: zero or more than one element child, or an element child that is none of the three defined qualifiers.</summary>
    Unrecognized = 0,

    /// <summary>A URL where a copy of the signature policy document can be obtained.</summary>
    SPURI,

    /// <summary>Information intended for display when the signature is validated.</summary>
    SPUserNotice,

    /// <summary>An identifier of the technical specification the signature policy document's own syntax follows.</summary>
    SPDocSpecification
}


/// <summary>
/// One <c>SigPolicyQualifier</c> entry of a <c>SigPolicyQualifiers</c> list (clause 5.2.9.1): the element's
/// own raw, unmodeled content (<see cref="Content"/>, always populated, since <c>SigPolicyQualifier</c> is
/// <c>AnyType</c> and so structurally cannot be refused) plus, when the element's content is recognizably one
/// of the three qualifiers clause 5.2.9.2 defines — exactly one element child matching a known name — that
/// qualifier's own parsed content, selected by <see cref="Kind"/>.
/// </summary>
/// <remarks>
/// Carries no owned pooled content of its own — every field is either a span computed from
/// <see cref="Table"/>, a nested <see cref="XAdESSPUserNotice"/>/<see cref="XAdESObjectIdentifier"/>, or an
/// <see cref="XAdESUnmodeledContent"/> — so no <see cref="IDisposable"/> surface is needed.
/// </remarks>
public readonly struct XAdESSigPolicyQualifierEntry: IEquatable<XAdESSigPolicyQualifierEntry>
{
    /// <summary>The table the entry's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>SigPolicyQualifier</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>The element's raw, unmodeled content — every immediate child node, unfiltered.</summary>
    public XAdESUnmodeledContent Content { get; }

    /// <summary>Which of the three defined qualifiers this entry recognizes, or <see cref="XAdESSigPolicyQualifierKind.Unrecognized"/>.</summary>
    public XAdESSigPolicyQualifierKind Kind { get; }

    private int SPURITextNodeIndex { get; }

    /// <summary>The <c>SPURI</c> content; valid when <see cref="Kind"/> is <see cref="XAdESSigPolicyQualifierKind.SPURI"/>.</summary>
    public ReadOnlySpan<byte> SPURI => Kind == XAdESSigPolicyQualifierKind.SPURI && SPURITextNodeIndex >= 0 ? Table.ValueOf(SPURITextNodeIndex) : ReadOnlySpan<byte>.Empty;

    /// <summary>The <c>SPUserNotice</c> content; valid when <see cref="Kind"/> is <see cref="XAdESSigPolicyQualifierKind.SPUserNotice"/>.</summary>
    public XAdESSPUserNotice SPUserNotice { get; }

    /// <summary>The <c>SPDocSpecification</c> content; valid when <see cref="Kind"/> is <see cref="XAdESSigPolicyQualifierKind.SPDocSpecification"/>.</summary>
    public XAdESObjectIdentifier SPDocSpecification { get; }


    private XAdESSigPolicyQualifierEntry(
        XmlNodeTable table,
        int elementIndex,
        XAdESUnmodeledContent content,
        XAdESSigPolicyQualifierKind kind,
        int spuriTextNodeIndex,
        XAdESSPUserNotice spUserNotice,
        XAdESObjectIdentifier spDocSpecification)
    {
        Table = table;
        ElementIndex = elementIndex;
        Content = content;
        Kind = kind;
        SPURITextNodeIndex = spuriTextNodeIndex;
        SPUserNotice = spUserNotice;
        SPDocSpecification = spDocSpecification;
    }


    /// <summary>
    /// Reads one <c>SigPolicyQualifier</c> entry: its raw content, always; and, only when that content is
    /// exactly one element child matching <c>SPURI</c>/<c>SPUserNotice</c> (namespace
    /// <see cref="XAdESIdentifiers.XAdESNamespaceV132"/>) or <c>SPDocSpecification</c> (namespace
    /// <see cref="XAdESIdentifiers.XAdESNamespaceV141"/>), that qualifier's own parsed content. Never refuses
    /// for content it does not recognize — only a recognized qualifier whose own inner shape is malformed
    /// propagates a refusal.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int sigPolicyQualifierElementIndex, out XAdESSigPolicyQualifierEntry value, out XAdESReadError error)
    {
        XAdESUnmodeledContent content = XAdESUnmodeledContent.Read(table, sigPolicyQualifierElementIndex);
        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, sigPolicyQualifierElementIndex, out int child);
        if(scan == ElementScanResult.Found)
        {
            ElementScanResult trailingScan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out _);
            if(trailingScan == ElementScanResult.EndOfChildren)
            {
                if(XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SPURI"u8))
                {
                    if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out XmlSignatureReadError grammarError)
                        || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out int spuriTextNodeIndex, out grammarError))
                    {
                        value = default;
                        error = XAdESGrammar.FromGrammarFailure(grammarError);

                        return false;
                    }

                    value = new XAdESSigPolicyQualifierEntry(table, sigPolicyQualifierElementIndex, content, XAdESSigPolicyQualifierKind.SPURI, spuriTextNodeIndex, default, default);
                    error = default;

                    return true;
                }

                if(XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SPUserNotice"u8))
                {
                    if(!XAdESSPUserNotice.TryRead(table, child, out XAdESSPUserNotice userNotice, out error))
                    {
                        value = default;

                        return false;
                    }

                    value = new XAdESSigPolicyQualifierEntry(table, sigPolicyQualifierElementIndex, content, XAdESSigPolicyQualifierKind.SPUserNotice, -1, userNotice, default);
                    error = default;

                    return true;
                }

                if(XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV141Utf8, "SPDocSpecification"u8))
                {
                    if(!XAdESSPDocSpecification.TryRead(table, child, out XAdESObjectIdentifier spDocSpecification, out error))
                    {
                        value = default;

                        return false;
                    }

                    value = new XAdESSigPolicyQualifierEntry(table, sigPolicyQualifierElementIndex, content, XAdESSigPolicyQualifierKind.SPDocSpecification, -1, default, spDocSpecification);
                    error = default;

                    return true;
                }
            }
        }

        value = new XAdESSigPolicyQualifierEntry(table, sigPolicyQualifierElementIndex, content, XAdESSigPolicyQualifierKind.Unrecognized, -1, default, default);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESSigPolicyQualifierEntry other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESSigPolicyQualifierEntry other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESSigPolicyQualifierEntry left, XAdESSigPolicyQualifierEntry right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESSigPolicyQualifierEntry left, XAdESSigPolicyQualifierEntry right) => !left.Equals(right);
}

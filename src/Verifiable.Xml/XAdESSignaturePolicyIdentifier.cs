using System.Collections.Generic;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The <c>SignaturePolicyId</c> qualifying property content of clause 5.2.9.1: a mandatory <c>SigPolicyId</c>
/// (the shared <c>ObjectIdentifierType</c> reader), an optional <c>ds:Transforms</c> chain describing how the
/// signature policy document is processed before hashing (the shared reference-processing transform model,
/// reused via <see cref="XmlTransform.TryReadList"/> for this standalone, non-<c>Reference</c> occurrence of
/// <c>ds:Transforms</c>), a mandatory <c>SigPolicyHash</c> (the shared <c>DigestAlgAndValueType</c> reader),
/// and an optional, open <c>SigPolicyQualifiers</c> list.
/// </summary>
/// <remarks>
/// Enforces clause 5.2.9.1's own read-level cross-check: "If this transform is used, then the
/// <c>SignaturePolicyIdentifier</c> shall be qualified at least by the <c>SPDocSpecification</c> qualifier" —
/// when <see cref="Transforms"/> names <see cref="XAdESIdentifiers.SPDocDigestAsInSpecificationTransformUri"/>,
/// <see cref="TryRead"/> refuses unless <see cref="SigPolicyQualifiers"/> carries at least one
/// <see cref="XAdESSigPolicyQualifierKind.SPDocSpecification"/> entry (<see cref="XAdESReadFailure.SPDocDigestAsInSpecificationRequiresSPDocSpecification"/>).
/// The converse never triggers this refusal: an <c>SPDocSpecification</c> qualifier without the transform is
/// unconstrained by this rule. This is the first clause-5.2.9 reader that owns pooled content of its own (via
/// <see cref="SigPolicyHash"/>'s digest octets), so — like <see cref="XAdESSigningCertificateV2"/> — it is
/// itself <see cref="IDisposable"/>.
/// </remarks>
public sealed class XAdESSignaturePolicyId: IDisposable
{
    /// <summary>The document the property was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>SignaturePolicyId</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>The <c>SigPolicyId</c> child: a specific-version identifier of the signature policy.</summary>
    public XAdESObjectIdentifier SigPolicyId { get; }

    /// <summary>Whether the optional <c>ds:Transforms</c> child is present.</summary>
    public bool HasTransforms { get; }

    /// <summary>
    /// The transformations performed on the signature policy document before hashing, in document order;
    /// empty when <see cref="HasTransforms"/> is <see langword="false"/>.
    /// </summary>
    public IReadOnlyList<XmlTransform> Transforms { get; }

    /// <summary>The <c>SigPolicyHash</c> child: the signature policy document's digest algorithm and value.</summary>
    public XAdESDigestAlgAndValue SigPolicyHash { get; }

    /// <summary>Whether the optional <c>SigPolicyQualifiers</c> child is present.</summary>
    public bool HasSigPolicyQualifiers { get; }

    /// <summary>
    /// The <c>SigPolicyQualifier</c> entries, in document order; non-empty when
    /// <see cref="HasSigPolicyQualifiers"/> is <see langword="true"/>, empty otherwise.
    /// </summary>
    public IReadOnlyList<XAdESSigPolicyQualifierEntry> SigPolicyQualifiers { get; }

    private List<PooledMemory> OwnedContent { get; }

    private bool isDisposed;


    private XAdESSignaturePolicyId(
        XmlNodeTable table,
        int elementIndex,
        XAdESObjectIdentifier sigPolicyId,
        bool hasTransforms,
        IReadOnlyList<XmlTransform> transforms,
        XAdESDigestAlgAndValue sigPolicyHash,
        bool hasSigPolicyQualifiers,
        IReadOnlyList<XAdESSigPolicyQualifierEntry> sigPolicyQualifiers,
        List<PooledMemory> ownedContent)
    {
        Table = table;
        ElementIndex = elementIndex;
        SigPolicyId = sigPolicyId;
        HasTransforms = hasTransforms;
        Transforms = transforms;
        SigPolicyHash = sigPolicyHash;
        HasSigPolicyQualifiers = hasSigPolicyQualifiers;
        SigPolicyQualifiers = sigPolicyQualifiers;
        OwnedContent = ownedContent;
    }


    /// <summary>
    /// Reads a <c>SignaturePolicyId</c> element: no attributes of its own, then <c>SigPolicyId</c>, optional
    /// <c>ds:Transforms</c>, <c>SigPolicyHash</c> and optional <c>SigPolicyQualifiers</c>, in that fixed
    /// order.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>SignaturePolicyId</c> element.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.MissingRequiredChild"/> when <c>SigPolicyId</c> or <c>SigPolicyHash</c> is
    /// absent; <see cref="XAdESReadFailure.SPDocDigestAsInSpecificationRequiresSPDocSpecification"/> per this
    /// type's own cross-check.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESSignaturePolicyId? value, out XAdESReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(pool);
        value = null;
        var owned = new List<PooledMemory>();
        try
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out XmlSignatureReadError grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
            if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SigPolicyId"u8))
            {
                error = new XAdESReadError(
                    scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

                return false;
            }

            if(!XAdESObjectIdentifier.TryRead(table, child, out XAdESObjectIdentifier sigPolicyId, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }

            if(scan != ElementScanResult.Found)
            {
                error = new XAdESReadError(XAdESReadFailure.MissingRequiredChild, 0);

                return false;
            }

            bool hasTransforms = false;
            List<XmlTransform> transforms = [];
            if(XmlSignatureModelGrammar.IsDsElement(table, child, "Transforms"u8))
            {
                if(!XmlTransform.TryReadList(table, child, out transforms, out XmlSignatureReadError transformsError))
                {
                    error = XAdESGrammar.FromGrammarFailure(transformsError);

                    return false;
                }

                hasTransforms = true;
                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
                if(scan == ElementScanResult.UnexpectedContent)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                    return false;
                }

                if(scan != ElementScanResult.Found)
                {
                    error = new XAdESReadError(XAdESReadFailure.MissingRequiredChild, 0);

                    return false;
                }
            }

            if(!XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SigPolicyHash"u8))
            {
                bool isRepeatTransforms = hasTransforms && XmlSignatureModelGrammar.IsDsElement(table, child, "Transforms"u8);
                error = new XAdESReadError(isRepeatTransforms ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            if(!XAdESDigestAlgAndValue.TryRead(table, child, pool, owned, out XAdESDigestAlgAndValue sigPolicyHash, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }

            bool hasSigPolicyQualifiers = false;
            var sigPolicyQualifiers = new List<XAdESSigPolicyQualifierEntry>();
            if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SigPolicyQualifiers"u8))
            {
                int qualifiersElementIndex = child;
                if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, qualifiersElementIndex, 0, out grammarError))
                {
                    error = XAdESGrammar.FromGrammarFailure(grammarError);

                    return false;
                }

                if(!XmlSignatureModelGrammar.TryReadElementChildren(table, qualifiersElementIndex, out List<int> qualifierElements, out grammarError))
                {
                    error = XAdESGrammar.FromGrammarFailure(grammarError);

                    return false;
                }

                if(qualifierElements.Count == 0)
                {
                    error = new XAdESReadError(XAdESReadFailure.MissingRequiredChild, 0);

                    return false;
                }

                foreach(int qualifierElement in qualifierElements)
                {
                    if(!XmlSignatureModelGrammar.IsElement(table, qualifierElement, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SigPolicyQualifier"u8))
                    {
                        error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

                        return false;
                    }

                    if(!XAdESSigPolicyQualifierEntry.TryRead(table, qualifierElement, out XAdESSigPolicyQualifierEntry entry, out error))
                    {
                        return false;
                    }

                    sigPolicyQualifiers.Add(entry);
                }

                hasSigPolicyQualifiers = true;
                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, qualifiersElementIndex, out child);
                if(scan == ElementScanResult.UnexpectedContent)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                    return false;
                }
            }

            if(scan == ElementScanResult.Found)
            {
                bool isRepeat = XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SigPolicyId"u8)
                    || (hasTransforms && XmlSignatureModelGrammar.IsDsElement(table, child, "Transforms"u8))
                    || XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SigPolicyHash"u8)
                    || (hasSigPolicyQualifiers && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SigPolicyQualifiers"u8));
                error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            bool usesSPDocDigestTransform = false;
            foreach(XmlTransform transform in transforms)
            {
                if(transform.Algorithm.SequenceEqual(XAdESIdentifiers.SPDocDigestAsInSpecificationTransformUriUtf8))
                {
                    usesSPDocDigestTransform = true;

                    break;
                }
            }

            if(usesSPDocDigestTransform)
            {
                bool hasSPDocSpecificationQualifier = false;
                foreach(XAdESSigPolicyQualifierEntry qualifier in sigPolicyQualifiers)
                {
                    if(qualifier.Kind == XAdESSigPolicyQualifierKind.SPDocSpecification)
                    {
                        hasSPDocSpecificationQualifier = true;

                        break;
                    }
                }

                if(!hasSPDocSpecificationQualifier)
                {
                    error = new XAdESReadError(XAdESReadFailure.SPDocDigestAsInSpecificationRequiresSPDocSpecification, 0);

                    return false;
                }
            }

            value = new XAdESSignaturePolicyId(table, elementIndex, sigPolicyId, hasTransforms, transforms, sigPolicyHash, hasSigPolicyQualifiers, sigPolicyQualifiers, owned);
            error = default;

            return true;
        }
        finally
        {
            if(value is null)
            {
                for(int i = 0; i < owned.Count; ++i)
                {
                    owned[i].Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Tells whether this value was read over the given table instance — the identity guard this library
    /// requires before any processing that combines this value with another table-scoped argument.
    /// </summary>
    /// <param name="table">The table to check against.</param>
    /// <returns><see langword="true"/> when this value was read from the same table instance.</returns>
    public bool IsOver(XmlNodeTable table)
    {
        return ReferenceEquals(Table, table);
    }


    /// <summary>
    /// Releases <see cref="SigPolicyHash"/>'s decoded digest octets. <see cref="Table"/> is not owned and is
    /// not disposed here. Idempotent.
    /// </summary>
    public void Dispose()
    {
        if(isDisposed)
        {
            return;
        }

        isDisposed = true;
        for(int i = 0; i < OwnedContent.Count; ++i)
        {
            OwnedContent[i].Dispose();
        }
    }
}


/// <summary>
/// Which arm of <c>SignaturePolicyIdentifierType</c>'s <c>SignaturePolicyId</c>/<c>SignaturePolicyImplied</c>
/// choice (clause 5.2.9.1) an <see cref="XAdESSignaturePolicyIdentifier"/> holds.
/// </summary>
public enum XAdESSignaturePolicyIdentifierChoice
{
    /// <summary>An explicit identifier of a signature policy, carried by <see cref="XAdESSignaturePolicyIdentifier.SignaturePolicyId"/>.</summary>
    SignaturePolicyId,

    /// <summary>The empty <c>SignaturePolicyImplied</c> marker: the signature policy is implied by the signed data object(s) and other external data.</summary>
    SignaturePolicyImplied
}


/// <summary>
/// The <c>SignaturePolicyIdentifier</c> qualifying property of clause 5.2.9.1: a signed qualifying property
/// qualifying the signature, containing either an explicit signature policy identifier
/// (<see cref="XAdESSignaturePolicyIdentifierChoice.SignaturePolicyId"/>, <see cref="XAdESSignaturePolicyId"/>)
/// or the empty <c>SignaturePolicyImplied</c> marker
/// (<see cref="XAdESSignaturePolicyIdentifierChoice.SignaturePolicyImplied"/>).
/// </summary>
/// <remarks>
/// Owns <see cref="SignaturePolicyId"/> when <see cref="Choice"/> selects it — the only arm carrying pooled
/// content — so this type is itself <see cref="IDisposable"/>, delegating to that value's own
/// <see cref="XAdESSignaturePolicyId.Dispose"/>.
/// </remarks>
public sealed class XAdESSignaturePolicyIdentifier: IDisposable
{
    /// <summary>The document the property was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>SignaturePolicyIdentifier</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Which arm of the choice is present.</summary>
    public XAdESSignaturePolicyIdentifierChoice Choice { get; }

    /// <summary>
    /// The <c>SignaturePolicyId</c> content; non-<see langword="null"/> only when <see cref="Choice"/> is
    /// <see cref="XAdESSignaturePolicyIdentifierChoice.SignaturePolicyId"/>.
    /// </summary>
    public XAdESSignaturePolicyId? SignaturePolicyId { get; }

    private bool isDisposed;


    private XAdESSignaturePolicyIdentifier(XmlNodeTable table, int elementIndex, XAdESSignaturePolicyIdentifierChoice choice, XAdESSignaturePolicyId? signaturePolicyId)
    {
        Table = table;
        ElementIndex = elementIndex;
        Choice = choice;
        SignaturePolicyId = signaturePolicyId;
    }


    /// <summary>
    /// Reads a <c>SignaturePolicyIdentifier</c> element: no attributes of its own, then exactly one child
    /// matching the <c>SignaturePolicyId</c>/<c>SignaturePolicyImplied</c> choice.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>SignaturePolicyIdentifier</c> element — typically obtained from a
    /// <see cref="XAdESSignedSignaturePropertyEntry"/> whose <see cref="XAdESSignedSignaturePropertyEntry.Name"/>
    /// is <see cref="XAdESSignedSignaturePropertyName.SignaturePolicyIdentifier"/>.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure — see <see cref="XAdESSignaturePolicyId.TryRead"/> for the
    /// <see cref="XAdESSignaturePolicyIdentifierChoice.SignaturePolicyId"/> arm.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    /// <remarks>
    /// <strong>Manual disposal, not a <see langword="using"/> declaration.</strong> <c>signaturePolicyId</c>
    /// transfers ownership into <paramref name="value"/> on success — nulled just before the return so the
    /// <see langword="finally"/> disposes it only when a later grammar check fails first.
    /// </remarks>
    public static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESSignaturePolicyIdentifier? value, out XAdESReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(pool);
        value = null;
        XAdESSignaturePolicyId? signaturePolicyId = null;
        try
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out XmlSignatureReadError grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
            if(scan != ElementScanResult.Found)
            {
                error = new XAdESReadError(
                    scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

                return false;
            }

            bool isSignaturePolicyId = XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SignaturePolicyId"u8);
            bool isSignaturePolicyImplied = !isSignaturePolicyId && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SignaturePolicyImplied"u8);
            if(!isSignaturePolicyId && !isSignaturePolicyImplied)
            {
                error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            XAdESSignaturePolicyIdentifierChoice choice;
            if(isSignaturePolicyId)
            {
                choice = XAdESSignaturePolicyIdentifierChoice.SignaturePolicyId;
                if(!XAdESSignaturePolicyId.TryRead(table, child, pool, out signaturePolicyId, out error))
                {
                    return false;
                }
            }
            else
            {
                choice = XAdESSignaturePolicyIdentifierChoice.SignaturePolicyImplied;

                //SignaturePolicyImplied is the empty marker XA-5.2.9.1's schema names via a type-less
                //element declaration, the same shape AllSignedDataObjects (clause 5.2.3) takes: only an
                //actual element or non-whitespace text child makes it non-empty.
                if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError))
                {
                    error = XAdESGrammar.FromGrammarFailure(grammarError);

                    return false;
                }

                ElementScanResult impliedScan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, child, out _);
                if(impliedScan != ElementScanResult.EndOfChildren)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                    return false;
                }
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out int trailing);
            if(scan != ElementScanResult.EndOfChildren)
            {
                //One disjunct per xsd:choice/xsd:sequence sibling this element can repeat; a named
                //predicate per sibling would only rename the grammar, not simplify it.
                bool isRepeat = scan == ElementScanResult.Found
                    && ((isSignaturePolicyId && XmlSignatureModelGrammar.IsElement(table, trailing, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SignaturePolicyId"u8))
                        || (isSignaturePolicyImplied && XmlSignatureModelGrammar.IsElement(table, trailing, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SignaturePolicyImplied"u8)));
                error = new XAdESReadError(
                    scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent
                    : isRepeat ? XAdESReadFailure.DuplicateCoreChild
                    : XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            value = new XAdESSignaturePolicyIdentifier(table, elementIndex, choice, signaturePolicyId);
            signaturePolicyId = null;
            error = default;

            return true;
        }
        finally
        {
            signaturePolicyId?.Dispose();
        }
    }


    /// <summary>
    /// Tells whether this value was read over the given table instance — the identity guard this library
    /// requires before any processing that combines this value with another table-scoped argument.
    /// </summary>
    /// <param name="table">The table to check against.</param>
    /// <returns><see langword="true"/> when this value was read from the same table instance.</returns>
    public bool IsOver(XmlNodeTable table)
    {
        return ReferenceEquals(Table, table);
    }


    /// <summary>
    /// Releases <see cref="SignaturePolicyId"/>'s owned content, when present. <see cref="Table"/> is not
    /// owned and is not disposed here. Idempotent.
    /// </summary>
    public void Dispose()
    {
        if(isDisposed)
        {
            return;
        }

        isDisposed = true;
        SignaturePolicyId?.Dispose();
    }
}

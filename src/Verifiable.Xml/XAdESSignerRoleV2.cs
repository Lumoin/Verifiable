using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// Which arm of <c>CertifiedRoleTypeV2</c>'s <c>X509AttributeCertificate</c>/<c>OtherAttributeCertificate</c>
/// choice (clause 5.2.6) a <see cref="XAdESCertifiedRole"/> holds.
/// </summary>
public enum XAdESCertifiedRoleKind
{
    /// <summary>A base-64 encoded, DER-encoded ITU-T X.509 attribute certificate, within <c>X509AttributeCertificate</c>.</summary>
    X509AttributeCertificate,

    /// <summary>An attribute certificate in a syntax other than X.509, within <c>OtherAttributeCertificate</c> — out of this document's scope per clause 5.2.6.</summary>
    OtherAttributeCertificate
}


/// <summary>
/// One <c>CertifiedRole</c> entry of a <c>CertifiedRolesV2</c> list (clause 5.2.6's <c>CertifiedRoleTypeV2</c>):
/// exactly one of <see cref="X509AttributeCertificate"/> or <see cref="OtherAttributeCertificate"/> is
/// meaningful, selected by <see cref="Kind"/> — the two-way exhaustive choice clause 5.2.6 states ("which
/// shall be one of the following: the base-64 encoding of DER-encoded X509 attribute certificates ... within
/// the X509AttributeCertificate element; or attribute certificates ... in different syntax ... within the
/// OtherAttributeCertificate element"), the same two-arm-entry shape <see cref="XAdESTimeStampEntry"/> takes
/// for <c>GenericTimeStampType</c>'s own choice.
/// </summary>
public readonly struct XAdESCertifiedRole: IEquatable<XAdESCertifiedRole>
{
    /// <summary>Which arm of the choice this entry holds.</summary>
    public XAdESCertifiedRoleKind Kind { get; }

    /// <summary>The <c>X509AttributeCertificate</c> payload; meaningful only when <see cref="Kind"/> is <see cref="XAdESCertifiedRoleKind.X509AttributeCertificate"/>.</summary>
    public XAdESEncapsulatedPkiData X509AttributeCertificate { get; }

    /// <summary>The <c>OtherAttributeCertificate</c> payload; meaningful only when <see cref="Kind"/> is <see cref="XAdESCertifiedRoleKind.OtherAttributeCertificate"/>.</summary>
    public XAdESUnmodeledContent OtherAttributeCertificate { get; }


    private XAdESCertifiedRole(XAdESCertifiedRoleKind kind, XAdESEncapsulatedPkiData x509AttributeCertificate, XAdESUnmodeledContent otherAttributeCertificate)
    {
        Kind = kind;
        X509AttributeCertificate = x509AttributeCertificate;
        OtherAttributeCertificate = otherAttributeCertificate;
    }


    /// <summary>Wraps an <c>X509AttributeCertificate</c> payload.</summary>
    /// <param name="value">The read <c>X509AttributeCertificate</c>.</param>
    /// <returns>The wrapped entry.</returns>
    internal static XAdESCertifiedRole FromX509AttributeCertificate(XAdESEncapsulatedPkiData value) => new(XAdESCertifiedRoleKind.X509AttributeCertificate, value, default);


    /// <summary>Wraps an <c>OtherAttributeCertificate</c> payload.</summary>
    /// <param name="value">The unmodeled <c>OtherAttributeCertificate</c> content.</param>
    /// <returns>The wrapped entry.</returns>
    internal static XAdESCertifiedRole FromOtherAttributeCertificate(XAdESUnmodeledContent value) => new(XAdESCertifiedRoleKind.OtherAttributeCertificate, default, value);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESCertifiedRole other) =>
        Kind == other.Kind
        && (Kind == XAdESCertifiedRoleKind.X509AttributeCertificate ? X509AttributeCertificate.Equals(other.X509AttributeCertificate) : OtherAttributeCertificate.Equals(other.OtherAttributeCertificate));


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESCertifiedRole other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Kind == XAdESCertifiedRoleKind.X509AttributeCertificate ? HashCode.Combine(Kind, X509AttributeCertificate) : HashCode.Combine(Kind, OtherAttributeCertificate);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESCertifiedRole left, XAdESCertifiedRole right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESCertifiedRole left, XAdESCertifiedRole right) => !left.Equals(right);
}


/// <summary>
/// The <c>SignerRoleV2</c> qualifying property of clause 5.2.6: a signed qualifying property that qualifies
/// the signer, encapsulating signer attributes through three individually optional lists, in the acquired
/// v132 XSD's fixed <c>ClaimedRoles?, CertifiedRolesV2?, SignedAssertions?</c> sequence — claimed roles
/// (<c>ClaimedRole+</c>, each <c>AnyType</c>, carried unmodeled via <see cref="XAdESUnmodeledContent"/>),
/// certified roles (<c>CertifiedRole+</c>, each the <see cref="XAdESCertifiedRole"/> choice), and signed
/// third-party assertions (<c>SignedAssertion+</c>, each <c>AnyType</c>, unmodeled) — each list non-empty when
/// present, per both the schema's own <c>maxOccurs="unbounded"</c> default-<c>minOccurs="1"</c> and clause
/// 5.2.6's restating prose ("shall contain a non-empty sequence of..."). Clause 5.2.6 also narrows the
/// schema's "each of the three lists is independently optional" shape with its own floor the schema cannot
/// express: "Empty <c>SignerRoleV2</c> qualifying properties shall not be generated" — <see cref="TryRead"/>
/// enforces it explicitly, the same schema-permits/prose-forbids pattern
/// <see cref="XAdESSignatureProductionPlaceV2"/>'s own empty-property rule and
/// <see cref="XAdESDataObjectFormat"/>'s cross-child floor both apply.
/// </summary>
/// <remarks>
/// This is a clause-5.2 reader that decodes pooled content of its own (any <c>X509AttributeCertificate</c>
/// entry, via <see cref="XAdESEncapsulatedPkiData"/>), so — like <see cref="XAdESSigningCertificateV2"/> — it
/// is itself <see cref="IDisposable"/>, owning one flat custody list across every <see cref="CertifiedRoles"/>
/// entry's decoded fields.
/// </remarks>
public sealed class XAdESSignerRoleV2: IDisposable
{
    /// <summary>The document the property was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>SignerRoleV2</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>ClaimedRoles</c> child is present.</summary>
    public bool HasClaimedRoles { get; }

    /// <summary>The <c>ClaimedRole</c> entries' unmodeled content, in document order; non-empty when <see cref="HasClaimedRoles"/> is <see langword="true"/>, empty otherwise.</summary>
    public IReadOnlyList<XAdESUnmodeledContent> ClaimedRoles { get; }

    /// <summary>Whether the optional <c>CertifiedRolesV2</c> child is present.</summary>
    public bool HasCertifiedRolesV2 { get; }

    /// <summary>The <c>CertifiedRole</c> entries, in document order; non-empty when <see cref="HasCertifiedRolesV2"/> is <see langword="true"/>, empty otherwise.</summary>
    public IReadOnlyList<XAdESCertifiedRole> CertifiedRoles { get; }

    /// <summary>Whether the optional <c>SignedAssertions</c> child is present.</summary>
    public bool HasSignedAssertions { get; }

    /// <summary>The <c>SignedAssertion</c> entries' unmodeled content, in document order; non-empty when <see cref="HasSignedAssertions"/> is <see langword="true"/>, empty otherwise.</summary>
    public IReadOnlyList<XAdESUnmodeledContent> SignedAssertions { get; }

    private List<PooledMemory> OwnedContent { get; }

    private bool isDisposed;


    private XAdESSignerRoleV2(
        XmlNodeTable table,
        int elementIndex,
        bool hasClaimedRoles,
        IReadOnlyList<XAdESUnmodeledContent> claimedRoles,
        bool hasCertifiedRolesV2,
        IReadOnlyList<XAdESCertifiedRole> certifiedRoles,
        bool hasSignedAssertions,
        IReadOnlyList<XAdESUnmodeledContent> signedAssertions,
        List<PooledMemory> ownedContent)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasClaimedRoles = hasClaimedRoles;
        ClaimedRoles = claimedRoles;
        HasCertifiedRolesV2 = hasCertifiedRolesV2;
        CertifiedRoles = certifiedRoles;
        HasSignedAssertions = hasSignedAssertions;
        SignedAssertions = signedAssertions;
        OwnedContent = ownedContent;
    }


    /// <summary>
    /// Reads a <c>SignerRoleV2</c> element: no attributes of its own, then its optional <c>ClaimedRoles</c>,
    /// <c>CertifiedRolesV2</c> and <c>SignedAssertions</c> children, in that fixed order, refusing an element
    /// with none of the three present.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>SignerRoleV2</c> element — typically obtained from a
    /// <see cref="XAdESSignedSignaturePropertyEntry"/> whose <see cref="XAdESSignedSignaturePropertyEntry.Name"/>
    /// is <see cref="XAdESSignedSignaturePropertyName.SignerRoleV2"/>.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.MissingRequiredChild"/> when a present list carries zero entries (clause
    /// 5.2.6's "non-empty sequence" rule on each of <c>ClaimedRoles</c>/<c>CertifiedRolesV2</c>/
    /// <c>SignedAssertions</c>); <see cref="XAdESReadFailure.EmptySignerRoleV2"/> when none of the three
    /// children is present at all (clause 5.2.6's "Empty ... shall not be generated").</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESSignerRoleV2? value, out XAdESReadError error)
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
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }

            bool hasClaimedRoles = false;
            var claimedRoles = new List<XAdESUnmodeledContent>();
            if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ClaimedRoles"u8))
            {
                int listElementIndex = child;
                if(!TryReadNonEmptyUnmodeledList(table, listElementIndex, "ClaimedRole"u8, claimedRoles, out error))
                {
                    return false;
                }

                hasClaimedRoles = true;
                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, listElementIndex, out child);
                if(scan == ElementScanResult.UnexpectedContent)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                    return false;
                }
            }

            bool hasCertifiedRolesV2 = false;
            var certifiedRoles = new List<XAdESCertifiedRole>();
            if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CertifiedRolesV2"u8))
            {
                int listElementIndex = child;
                if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, listElementIndex, 0, out grammarError))
                {
                    error = XAdESGrammar.FromGrammarFailure(grammarError);

                    return false;
                }

                if(!XmlSignatureModelGrammar.TryReadElementChildren(table, listElementIndex, out List<int> certifiedRoleElements, out grammarError))
                {
                    error = XAdESGrammar.FromGrammarFailure(grammarError);

                    return false;
                }

                if(certifiedRoleElements.Count == 0)
                {
                    error = new XAdESReadError(XAdESReadFailure.MissingRequiredChild, 0);

                    return false;
                }

                foreach(int certifiedRoleElement in certifiedRoleElements)
                {
                    if(!XmlSignatureModelGrammar.IsElement(table, certifiedRoleElement, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CertifiedRole"u8))
                    {
                        error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

                        return false;
                    }

                    if(!TryReadCertifiedRole(table, certifiedRoleElement, pool, owned, out XAdESCertifiedRole certifiedRole, out error))
                    {
                        return false;
                    }

                    certifiedRoles.Add(certifiedRole);
                }

                hasCertifiedRolesV2 = true;
                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, listElementIndex, out child);
                if(scan == ElementScanResult.UnexpectedContent)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                    return false;
                }
            }

            bool hasSignedAssertions = false;
            var signedAssertions = new List<XAdESUnmodeledContent>();
            if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SignedAssertions"u8))
            {
                int listElementIndex = child;
                if(!TryReadNonEmptyUnmodeledList(table, listElementIndex, "SignedAssertion"u8, signedAssertions, out error))
                {
                    return false;
                }

                hasSignedAssertions = true;
                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, listElementIndex, out child);
                if(scan == ElementScanResult.UnexpectedContent)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                    return false;
                }
            }

            if(scan == ElementScanResult.Found)
            {
                //One disjunct per xsd:sequence child this element can repeat; a named predicate per child
                //would only rename the grammar, not simplify it.
                bool isRepeat = (hasClaimedRoles && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ClaimedRoles"u8))
                    || (hasCertifiedRolesV2 && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CertifiedRolesV2"u8))
                    || (hasSignedAssertions && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SignedAssertions"u8));
                error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            if(!hasClaimedRoles && !hasCertifiedRolesV2 && !hasSignedAssertions)
            {
                error = new XAdESReadError(XAdESReadFailure.EmptySignerRoleV2, 0);

                return false;
            }

            value = new XAdESSignerRoleV2(table, elementIndex, hasClaimedRoles, claimedRoles, hasCertifiedRolesV2, certifiedRoles, hasSignedAssertions, signedAssertions, owned);
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
    /// Reads a <c>ClaimedRoles</c>/<c>SignedAssertions</c>-shaped list element: no attributes, then a
    /// non-empty sequence of same-named <c>AnyType</c> children, each carried unmodeled.
    /// </summary>
    private static bool TryReadNonEmptyUnmodeledList(XmlNodeTable table, int listElementIndex, ReadOnlySpan<byte> memberLocalName, List<XAdESUnmodeledContent> entries, out XAdESReadError error)
    {
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, listElementIndex, 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryReadElementChildren(table, listElementIndex, out List<int> memberElements, out grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        if(memberElements.Count == 0)
        {
            error = new XAdESReadError(XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        foreach(int memberElement in memberElements)
        {
            if(!XmlSignatureModelGrammar.IsElement(table, memberElement, XAdESIdentifiers.XAdESNamespaceV132Utf8, memberLocalName))
            {
                error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            entries.Add(XAdESUnmodeledContent.Read(table, memberElement));
        }

        error = default;

        return true;
    }


    /// <summary>
    /// Reads one <c>CertifiedRole</c> element: no attributes of its own, then exactly one child matching the
    /// <c>X509AttributeCertificate</c>/<c>OtherAttributeCertificate</c> choice.
    /// </summary>
    private static bool TryReadCertifiedRole(XmlNodeTable table, int certifiedRoleElementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XAdESCertifiedRole value, out XAdESReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, certifiedRoleElementIndex, 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, certifiedRoleElementIndex, out int choiceChild);
        if(scan != ElementScanResult.Found)
        {
            error = new XAdESReadError(scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        bool isX509 = XmlSignatureModelGrammar.IsElement(table, choiceChild, XAdESIdentifiers.XAdESNamespaceV132Utf8, "X509AttributeCertificate"u8);
        bool isOther = !isX509 && XmlSignatureModelGrammar.IsElement(table, choiceChild, XAdESIdentifiers.XAdESNamespaceV132Utf8, "OtherAttributeCertificate"u8);
        if(!isX509 && !isOther)
        {
            error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        if(isX509)
        {
            if(!XAdESEncapsulatedPkiData.TryRead(table, choiceChild, pool, owned, out XAdESEncapsulatedPkiData pkiData, out error))
            {
                return false;
            }

            value = XAdESCertifiedRole.FromX509AttributeCertificate(pkiData);
        }
        else
        {
            value = XAdESCertifiedRole.FromOtherAttributeCertificate(XAdESUnmodeledContent.Read(table, choiceChild));
        }

        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, choiceChild, out int trailing);
        if(scan != ElementScanResult.EndOfChildren)
        {
            //One disjunct per xsd:choice sibling this element can repeat; a named predicate per sibling
            //would only rename the grammar, not simplify it.
            bool isRepeat = scan == ElementScanResult.Found
                && ((isX509 && XmlSignatureModelGrammar.IsElement(table, trailing, XAdESIdentifiers.XAdESNamespaceV132Utf8, "X509AttributeCertificate"u8))
                    || (isOther && XmlSignatureModelGrammar.IsElement(table, trailing, XAdESIdentifiers.XAdESNamespaceV132Utf8, "OtherAttributeCertificate"u8)));
            error = new XAdESReadError(
                scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent
                : isRepeat ? XAdESReadFailure.DuplicateCoreChild
                : XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        error = default;

        return true;
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
    /// Releases every decoded field every <see cref="CertifiedRoles"/> entry owns. <see cref="Table"/> is not
    /// owned and is not disposed here. Idempotent.
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

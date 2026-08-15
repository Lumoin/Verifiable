namespace Verifiable.Xml;

/// <summary>
/// The reason a canonicalization operation was refused.
/// </summary>
/// <remarks>
/// Canonicalization is result-shaped: a refusal is reported as an <see cref="XmlCanonicalizationError"/>
/// carrying one of these reasons, never as an exception. Document-content refusals belong to the reading
/// surface and its <see cref="XmlReadFailure"/> reasons; what remains here are the refusals only a
/// canonicalization request can produce.
/// </remarks>
public enum XmlCanonicalizationFailure
{
    /// <summary>
    /// The node-set is not one of the three shapes this library canonicalizes: the whole document, an element
    /// subtree with ancestor context, or a subtree minus excluded subtrees. General XPath node-set input is
    /// the SHOULD-level capability of
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.1 and is
    /// not provided; the three shapes are what XML Signature same-document references and the
    /// enveloped-signature transform produce.
    /// </summary>
    UnsupportedNodeSet,

    /// <summary>
    /// A token of the <c>InclusiveNamespaces PrefixList</c> parameter of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 4 is neither a namespace prefix of the <c>NCName</c> production nor the
    /// <c>#default</c> token.
    /// </summary>
    InvalidPrefixList,

    /// <summary>
    /// A node index the node-set was constructed over does not name an element node of the node table the
    /// canonicalization was asked to render.
    /// </summary>
    InvalidNodeIndex
}

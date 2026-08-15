namespace Verifiable.Xml;

/// <summary>
/// The reason reference processing — dereferencing a <c>ds:Reference</c>'s <c>URI</c>, running its
/// transform chain, or producing the canonical <c>SignedInfo</c> octets — was refused, per
/// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see> sections 4.3.3 and 6.6.
/// </summary>
/// <remarks>
/// Reference processing is result-shaped: a refusal is reported as an <see cref="XmlSignatureProcessingError"/>
/// carrying one of these reasons, never as an exception over input content. <see cref="IdNotFound"/> and
/// <see cref="DuplicateId"/> are produced by <see cref="XmlNodeTable.TryFindElementById"/> already; the rest
/// name the dispositions this reference-processing engine produces.
/// </remarks>
public enum XmlSignatureProcessingFailure
{
    /// <summary>
    /// A <c>Transform</c>'s <c>Algorithm</c> URI names no algorithm this leaf recognizes at all, per the
    /// section 6.6 chapeau's "Algorithm Identifiers and Implementation Requirements".
    /// </summary>
    UnsupportedTransform,

    /// <summary>
    /// The <c>Transform</c> names the XPath filtering transform of section 6.6.3 ("Recommended") or the
    /// XML-Signature XPath Filter 2.0 transform clause 6.3(g) of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> requires "shall be supported": both are recognized identifiers, but
    /// executing either needs the hand-rolled XPath 1.0 evaluator this leaf does not build.
    /// </summary>
    TransformNotYetSupported,

    /// <summary>
    /// The <c>Transform</c> names the XSLT transform of section 6.6.5 ("Optional") or the OOXML package
    /// Relationships transform (ECMA-376): both are recognized identifiers this leaf refuses to execute —
    /// running an attacker-supplied XSLT stylesheet is the section 8.3 "unacceptable processing or memory
    /// demand" class this surface's document type declaration refusal already closes the door on for the
    /// same reason, and OPC package signing is outside this leaf's supported document classes.
    /// </summary>
    TransformRefused,

    /// <summary>
    /// The <c>SignedInfo</c>'s <c>CanonicalizationMethod Algorithm</c> is not one of the six canonicalization
    /// identifiers clause 6.3(d) of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> requires a validator to support.
    /// </summary>
    UnsupportedCanonicalizationMethod,

    /// <summary>
    /// A same-document <c>Reference</c>'s fragment is not one of the four recognized forms — the null
    /// fragment, a bare-name XPointer, <c>#xpointer(/)</c> or <c>#xpointer(id(...))</c> — of section
    /// 4.3.3.2/.3.
    /// </summary>
    UnsupportedXPointer,

    /// <summary>
    /// A <c>Reference</c> carries no <c>URI</c> attribute at all — the section 4.3.3.1 "application
    /// context" case, refused because it has no use in the document classes this library models.
    /// </summary>
    UriOmitted,

    /// <summary>
    /// No recognized <c>ID</c>-typed attribute in the document carries the value
    /// <see cref="XmlNodeTable.TryFindElementById"/> was asked to resolve.
    /// </summary>
    IdNotFound,

    /// <summary>
    /// More than one recognized <c>ID</c>-typed attribute in the document carries the value
    /// <see cref="XmlNodeTable.TryFindElementById"/> was asked to resolve. Ambiguous targets are how
    /// signature-wrapping attacks work, so a duplicate refuses rather than resolving to the first match.
    /// </summary>
    DuplicateId,

    /// <summary>
    /// A non-same-document <c>Reference</c> needs dereferencing but no resolver delegate was supplied, or
    /// the supplied one reported failure. This leaf performs no I/O of its own.
    /// </summary>
    ExternalReferenceUnresolved,

    /// <summary>
    /// The section 4.3.3.2 default conversion of an octet stream into an XPath node-set — a well-formed
    /// parse through <see cref="XmlNodeTable.TryParse"/> — failed mid-chain. The
    /// <see cref="XmlSignatureProcessingError.InnerReadError"/> carries the parse's own
    /// <see cref="XmlReadError"/>.
    /// </summary>
    ReferenceParseFailed,

    /// <summary>
    /// A <c>Reference</c>'s transform chain carries more <c>Transform</c> elements than the documented
    /// hardening bound permits. XML Signature itself sets no such bound.
    /// </summary>
    TransformCountExceeded,

    /// <summary>
    /// A transform chain's octets-to-node-set re-parsing (the section 4.3.3.2 default conversion, applied
    /// repeatedly across successive transforms) exceeds the documented hardening depth bound.
    /// </summary>
    ReparseDepthExceeded,

    /// <summary>
    /// The base64 transform of section 6.6.2 was given content that does not match the
    /// <c>base64Binary</c> lexical space once XML white space is stripped and, when the transform's input
    /// was a node-set, its text-node string-value was concatenated — the same lexical rule
    /// <see cref="XmlSignatureReadFailure.InvalidBase64Content"/> names at model-read time, produced here
    /// instead because it surfaces while the transform chain executes rather than while the model reads.
    /// </summary>
    InvalidBase64Content,

    /// <summary>
    /// A canonicalization algorithm's own parameter — the <c>InclusiveNamespaces PrefixList</c> a
    /// <c>Transform</c> or a <c>SignedInfo</c>'s <c>CanonicalizationMethod</c> carries for the exclusive
    /// family — carries a token that is neither a namespace prefix of the <c>NCName</c> production nor the
    /// <c>#default</c> token, per section 4 of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see>; or the attribute value itself exceeds
    /// <see cref="XmlReferenceProcessing.MaximumPrefixListByteLength"/>, a documented hardening bound
    /// this library imposes — XML Signature itself sets no such bound.
    /// </summary>
    InvalidCanonicalizationParameter,

    /// <summary>
    /// The <c>table</c> argument <see cref="XmlReferenceProcessing"/>'s entry points were called with is not
    /// the identical <see cref="XmlNodeTable"/> instance the <c>Signature</c> or <c>Manifest</c> being
    /// processed was read over: the engine never processes a signature against a
    /// document other than the one it was itself read from, because doing so would silently retarget Id
    /// resolution and the enveloped-signature exclusion to the wrong document.
    /// </summary>
    TableMismatch,

    /// <summary>
    /// The enveloped-signature transform of section 6.6.4 was applied to a node-set that is not from the
    /// <c>Signature</c>'s own source document — a mid-chain octets-to-node-set re-parse (section 4.3.3.2's
    /// default conversion) produced an unrelated document instance before this transform ran. Section
    /// 6.6.4's defining <c>here()</c>-based XPath expression "results in an error if the
    /// containing XPath expression does not appear in the same XML document against which the XPath
    /// expression is being evaluated" (section 6.6.3's definition of <c>here()</c>), so this case is a
    /// refusal, never a silent pass-through of the unmodified node-set.
    /// </summary>
    EnvelopedSignatureSourceMismatch
}

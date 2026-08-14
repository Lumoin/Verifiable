namespace Verifiable.Xml;

/// <summary>
/// The reason an XML document was refused by the reading surface.
/// </summary>
/// <remarks>
/// <para>
/// Reading is result-shaped: a refusal is reported as an <see cref="XmlReadError"/> carrying one of these
/// reasons and the byte offset at which it was determined, never as an exception. The reasons are stable:
/// callers may branch on them.
/// </para>
/// <para>
/// The reading surface refuses every document type declaration outright, so the well-formedness constraints
/// of <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">Extensible Markup Language (XML) 1.0 (Fifth
/// Edition)</see> apply here as they read for a document with no DTD, and the namespace constraints of
/// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third Edition)</see>
/// are enforced in full.
/// </para>
/// </remarks>
public enum XmlReadFailure
{
    /// <summary>
    /// The document octets are in an encoding other than UTF-8 or UTF-16.
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.1 makes
    /// UTF-8 and UTF-16 the encodings an implementation is required to parse and leaves the rest optional;
    /// this surface refuses the rest instead of transcoding, so the section 2.1 Unicode Normalization Form C
    /// requirement for non-UCS source encodings is vacuously met.
    /// </summary>
    InvalidEncoding,

    /// <summary>
    /// A byte sequence in a UTF-8 document is not well-formed UTF-8. Refused rather than substituted with a
    /// replacement character, per the fatal-error rule of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 4.3.3.
    /// </summary>
    IllFormedUtf8,

    /// <summary>
    /// A code unit sequence in a UTF-16 document is not well-formed UTF-16, such as an unpaired surrogate or a
    /// truncated code unit. Refused rather than substituted with a replacement character, per the fatal-error
    /// rule of <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.3.3.
    /// </summary>
    IllFormedUtf16,

    /// <summary>
    /// The document carries a document type declaration
    /// (<see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.8).
    /// Refused outright: with no DTD there are no default attributes, no attribute types and no declared
    /// entities, which closes the entity-expansion and external-entity attack classes at the door.
    /// </summary>
    DoctypeProhibited,

    /// <summary>
    /// An entity reference names an entity other than the five predefined ones (amp, lt, gt, apos, quot). For
    /// a document with no DTD this is exactly the Entity Declared well-formedness constraint of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 4.1.
    /// </summary>
    UndeclaredEntity,

    /// <summary>
    /// A character in the document is outside the <c>Char</c> production of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.2.
    /// </summary>
    InvalidCharacter,

    /// <summary>
    /// A character reference does not denote a character of the <c>Char</c> production — the Legal Character
    /// well-formedness constraint of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 4.1.
    /// Unpaired-surrogate and out-of-range references are refused here.
    /// </summary>
    InvalidCharacterReference,

    /// <summary>
    /// A name violates the <c>Name</c> production of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.3 or
    /// the <c>NCName</c>/<c>QName</c> productions of
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third Edition)</see>.
    /// </summary>
    InvalidName,

    /// <summary>
    /// An end-tag names a different element type than the matching start-tag — the Element Type Match
    /// well-formedness constraint of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 3.1.
    /// </summary>
    MismatchedTag,

    /// <summary>
    /// An element carries two attributes with the same name — the Unique Att Spec well-formedness constraint
    /// of <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 3.1 —
    /// or two attributes with the same expanded name after namespace resolution, per
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third Edition)</see>
    /// section 6.3.
    /// </summary>
    DuplicateAttribute,

    /// <summary>
    /// A reserved prefix is misused per
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third Edition)</see>
    /// section 3: the <c>xml</c> prefix bound to a namespace name other than
    /// <c>http://www.w3.org/XML/1998/namespace</c>, that namespace name bound to another prefix, or a
    /// declaration involving the <c>xmlns</c> prefix or its namespace name.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1700:Do not name enum values 'Reserved'", Justification = "The member names the Namespaces in XML 1.0 section 3 constraint 'Reserved Prefixes and Namespace Names'; 'Reserved' is the specification's vocabulary for the xml and xmlns prefixes, not a placeholder for future use.")]
    ReservedPrefixMisuse,

    /// <summary>
    /// A namespace declaration for a prefix has an empty value.
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third Edition)</see>
    /// section 5 states the attribute value in a namespace declaration for a prefix MUST NOT be empty; prefix
    /// undeclaring exists only in XML 1.1. An empty default namespace declaration (<c>xmlns=""</c>) is legal
    /// and is not this refusal.
    /// </summary>
    PrefixUndeclarationProhibited,

    /// <summary>
    /// A namespace name is a relative URI reference, discriminated syntactically per
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-4.2">IETF RFC 3986 section 4.2</see> (no
    /// scheme means relative). <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML
    /// 1.0</see> section 2.1 requires implementations to report an operation failure on documents containing
    /// relative namespace URIs, and the reader is the surface that can still see them.
    /// </summary>
    RelativeNamespaceUri,

    /// <summary>
    /// A qualified name uses a prefix with no in-scope namespace declaration — the Prefix Declared namespace
    /// constraint of
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third Edition)</see>
    /// section 5.
    /// </summary>
    UndeclaredPrefix,

    /// <summary>
    /// Element nesting exceeds the maximum depth the reading surface documents. A refusal rather than
    /// unbounded recursion: reading is iterative and depth-bounded so an adversarial document cannot exhaust
    /// the stack.
    /// </summary>
    DepthLimitExceeded,

    /// <summary>
    /// The document octets end before the <c>document</c> production of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.1
    /// completes, such as inside a tag, a literal, a comment or before the root element closes.
    /// </summary>
    UnexpectedEndOfDocument,

    /// <summary>
    /// Markup violates a grammar production of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> not named by a
    /// more specific reason, such as <c>--</c> inside a comment (section 2.5), <c>]]&gt;</c> in character data
    /// (section 2.4) or a misplaced <c>?&gt;</c>.
    /// </summary>
    MalformedMarkup,

    /// <summary>
    /// The document has more than one root element, violating the <c>document</c> production of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.1,
    /// which permits exactly one element.
    /// </summary>
    MultipleRootElements
}

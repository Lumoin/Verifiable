namespace Verifiable.WebFinger;

/// <summary>
/// Library-default link relation types for the discovery uses this assembly serves.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-8">RFC 7033 §8</see> leaves the link relation
/// types to the application built on WebFinger; it defines none for discovering a DID from a handle. The
/// value here is a <strong>Verifiable-library convention</strong>, not an IANA-registered relation type.
/// </para>
/// <para>
/// It is deliberately expressed as a URI rather than a simple token, so that
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-8.6">RFC 7033 §8.6</see>'s rule that "a simple
/// token MUST be registered with IANA" does not apply. A deployment that follows a different convention
/// overrides it by passing its own relation type to the client's <c>relFilters</c> and returning that
/// relation from the server-side resolver.
/// </para>
/// </remarks>
public static class WebFingerLinkRelationTypes
{
    /// <summary>
    /// The default relation for a link whose <c>href</c> is the subject's DID: <c>urn:webfinger:did</c>.
    /// A library convention (see the type remarks), not IANA-registered; URI-form on purpose.
    /// </summary>
    /// <remarks>
    /// The relation's meaning is carried entirely by <c>href</c>: it MUST be the subject's DID — an external
    /// reference, per <see href="https://www.rfc-editor.org/rfc/rfc7033#section-8.4">RFC 7033 §8.4</see>. A
    /// link under this relation with no <c>href</c> is undefined by this convention; a resolver emitting one
    /// is a resolver-authoring error, not a form this library assigns a fallback semantic to.
    /// </remarks>
    public static string Did { get; } = "urn:webfinger:did";
}

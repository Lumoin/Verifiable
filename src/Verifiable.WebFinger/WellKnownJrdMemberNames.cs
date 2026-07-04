namespace Verifiable.WebFinger;

/// <summary>
/// The member names of a JSON Resource Descriptor (JRD) and its link relation objects, fixed by
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4">RFC 7033 §4.4</see>. The endpoint
/// serializer and the reference JRD deserializer read the same names from here.
/// </summary>
public static class WellKnownJrdMemberNames
{
    /// <summary>
    /// The JRD <c>subject</c> member — the URI the descriptor describes, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.1">RFC 7033 §4.4.1</see>.
    /// </summary>
    public static string Subject { get; } = "subject";

    /// <summary>
    /// The JRD <c>aliases</c> member — an array of URIs that identify the same entity as the subject,
    /// per <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.2">RFC 7033 §4.4.2</see>.
    /// </summary>
    public static string Aliases { get; } = "aliases";

    /// <summary>
    /// The JRD (or link) <c>properties</c> member — an object of URI-named values or null, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.3">RFC 7033 §4.4.3</see>.
    /// </summary>
    public static string Properties { get; } = "properties";

    /// <summary>
    /// The JRD <c>links</c> member — the array of link relation objects, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4">RFC 7033 §4.4.4</see>.
    /// </summary>
    public static string Links { get; } = "links";

    /// <summary>
    /// A link relation object's <c>rel</c> member — exactly one URI or registered relation type, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4.1">RFC 7033 §4.4.4.1</see>.
    /// </summary>
    public static string Rel { get; } = "rel";

    /// <summary>
    /// A link relation object's <c>type</c> member — the media type of the target resource, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4.2">RFC 7033 §4.4.4.2</see>.
    /// </summary>
    public static string Type { get; } = "type";

    /// <summary>
    /// A link relation object's <c>href</c> member — the target URI, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4.3">RFC 7033 §4.4.4.3</see>.
    /// </summary>
    public static string Href { get; } = "href";

    /// <summary>
    /// A link relation object's <c>titles</c> member — an object mapping language tags to human-readable
    /// titles, per <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4.4">RFC 7033 §4.4.4.4</see>.
    /// </summary>
    public static string Titles { get; } = "titles";
}

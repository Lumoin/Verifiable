using System.Collections.Generic;

namespace Verifiable.WebFinger;

/// <summary>
/// A JSON Resource Descriptor (JRD) — the representation a WebFinger resource returns for a query
/// target, per <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4">RFC 7033 §4.4</see>.
/// </summary>
/// <remarks>
/// <see cref="Subject"/> is nullable because §4.4.1 makes it a SHOULD, not a MUST. <see cref="Aliases"/>,
/// <see cref="Properties"/>, and <see cref="Links"/> are OPTIONAL (§4.4.2–§4.4.4) and default to empty so an
/// absent member and an empty member are handled uniformly. A client MUST ignore unknown members (§4.4);
/// this model carries only the specified ones, so an unknown member simply does not surface here.
/// </remarks>
public sealed record JsonResourceDescriptor
{
    /// <summary>
    /// The URI the descriptor describes, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.1">RFC 7033 §4.4.1</see>. SHOULD be
    /// present and MAY differ from the query's <c>resource</c>; <see langword="null"/> when absent.
    /// </summary>
    public string? Subject { get; init; }

    /// <summary>
    /// URIs that identify the same entity as <see cref="Subject"/>, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.2">RFC 7033 §4.4.2</see>.
    /// OPTIONAL — empty when absent.
    /// </summary>
    public IReadOnlyList<string> Aliases { get; init; } = [];

    /// <summary>
    /// URI-named values (or null) describing the subject, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.3">RFC 7033 §4.4.3</see>.
    /// OPTIONAL — empty when absent; a value MAY be <see langword="null"/>.
    /// </summary>
    public IReadOnlyDictionary<string, string?> Properties { get; init; } =
        new Dictionary<string, string?>();

    /// <summary>
    /// The link relation objects, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4">RFC 7033 §4.4.4</see>.
    /// OPTIONAL — empty when absent. Order MAY be interpreted as preference (§4.4.4).
    /// </summary>
    public IReadOnlyList<WebFingerLink> Links { get; init; } = [];
}

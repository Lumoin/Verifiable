using System.Collections.Generic;

namespace Verifiable.WebFinger;

/// <summary>
/// A link relation object within a JSON Resource Descriptor, per
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4">RFC 7033 §4.4.4</see>. It names a
/// relation the subject participates in and, usually, the target of that relation.
/// </summary>
/// <remarks>
/// <see cref="Rel"/> is required and single-valued, making the §4.4.4.1 "exactly one URI or registered
/// relation type" and "MUST be present" rules structural. Every other member is OPTIONAL (§4.4.4.2–§4.4.4.5)
/// and defaults to absent/empty so a link that carries only a relation is representable.
/// </remarks>
public sealed record WebFingerLink
{
    /// <summary>
    /// The relation type — exactly one URI or registered relation type, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4.1">RFC 7033 §4.4.4.1</see>.
    /// Required: a link relation object MUST carry a <c>rel</c>.
    /// </summary>
    public required string Rel { get; init; }

    /// <summary>
    /// The media type of the target resource, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4.2">RFC 7033 §4.4.4.2</see>.
    /// OPTIONAL — <see langword="null"/> when absent.
    /// </summary>
    public string? Type { get; init; }

    /// <summary>
    /// The target URI of the relation, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4.3">RFC 7033 §4.4.4.3</see>.
    /// OPTIONAL — <see langword="null"/> when the relation is conveyed by properties/titles alone.
    /// </summary>
    public string? Href { get; init; }

    /// <summary>
    /// Human-readable titles keyed by language tag (or <c>und</c>), per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4.4">RFC 7033 §4.4.4.4</see>.
    /// OPTIONAL — empty when absent. A dictionary makes the §4.4.4.4 "SHOULD NOT repeat a language tag"
    /// guidance structural (a language tag maps to a single title).
    /// </summary>
    public IReadOnlyDictionary<string, string> Titles { get; init; } =
        new Dictionary<string, string>();

    /// <summary>
    /// URI-named values (or null) describing the link, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4.5">RFC 7033 §4.4.4.5</see>.
    /// OPTIONAL — empty when absent; a value MAY be <see langword="null"/> (§4.4.3).
    /// </summary>
    public IReadOnlyDictionary<string, string?> Properties { get; init; } =
        new Dictionary<string, string?>();
}

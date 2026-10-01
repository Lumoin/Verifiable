using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Well-known HTTP query-parameter NAMES for the OpenID Federation 1.0
/// federation endpoints (§8). These are the <c>?name=value</c> keys a
/// requester places on the URL when calling a
/// <c>federation_fetch_endpoint</c> (section 8.1),
/// <c>federation_list_endpoint</c> (section 8.2) or
/// <c>federation_resolve_endpoint</c> (section 8.3); the matchers and input builders
/// in <see cref="FederationEndpoints"/> read them by these names rather
/// than by inline string literals.
/// </summary>
/// <remarks>
/// These are the NAMES of the request parameters, not their values — they
/// are the federation-endpoint analogue of
/// <see cref="OAuthRequestParameterNames"/>. The
/// <see cref="FederationMetadataParameterNames"/> sibling carries the
/// metadata-document keys (the endpoint URLs); this class carries the
/// query keys those endpoints accept.
/// </remarks>
public static class FederationEndpointParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="Sub"/>.</summary>
    public static ReadOnlySpan<byte> SubUtf8 => "sub"u8;

    /// <summary>
    /// <c>sub</c> — the Entity Identifier the requester is asking about at
    /// the <c>federation_fetch_endpoint</c> per Federation §8.1.
    /// </summary>
    public static string Sub { get; } = Utf8Constants.ToInternedString(SubUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EntityType"/>.</summary>
    public static ReadOnlySpan<byte> EntityTypeUtf8 => "entity_type"u8;

    /// <summary>
    /// <c>entity_type</c> — restricts a <c>federation_list_endpoint</c>
    /// response to subordinates declaring this Entity Type per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.2.1">Federation section 8.2.1</see>:
    /// "When multiple entity_type parameters are present, for example
    /// entity_type=openid_provider&amp;entity_type=openid_relying_party, the result
    /// MUST be filtered to include all specified Entity Types." It names an Entity
    /// Type whose resolved metadata a <c>federation_resolve_endpoint</c> returns per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3.1">Federation section 8.3.1</see>:
    /// "OPTIONAL. A specific Entity Type to resolve." and "If this parameter is
    /// not present, then all Entity Types are returned." and "The
    /// entity_type request parameter MAY occur multiple times, in which case,
    /// data for each Entity Type whose Entity Type Identifier is in an
    /// entity_type parameter value is returned."
    /// </summary>
    public static string EntityType { get; } = Utf8Constants.ToInternedString(EntityTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustAnchor"/>.</summary>
    public static ReadOnlySpan<byte> TrustAnchorUtf8 => "trust_anchor"u8;

    /// <summary>
    /// <c>trust_anchor</c>: the Trust Anchor against which a
    /// <c>federation_resolve_endpoint</c> resolves the subject per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3.1">Federation section 8.3.1</see>:
    /// "REQUIRED. The Trust Anchor that the resolve endpoint MUST use when
    /// resolving the metadata. The value is an Entity Identifier." and "The
    /// trust_anchor request parameter MAY occur multiple times, in which case,
    /// the resolver MAY return a successful resolve response using any of the
    /// Trust Anchor values provided."
    /// </summary>
    public static string TrustAnchor { get; } = Utf8Constants.ToInternedString(TrustAnchorUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustMarked"/>.</summary>
    public static ReadOnlySpan<byte> TrustMarkedUtf8 => "trust_marked"u8;

    /// <summary>
    /// <c>trust_marked</c> — restricts a <c>federation_list_endpoint</c>
    /// response to subordinates holding at least one Trust Mark per
    /// Federation §8.2.
    /// </summary>
    public static string TrustMarked { get; } = Utf8Constants.ToInternedString(TrustMarkedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustMarkType"/>.</summary>
    public static ReadOnlySpan<byte> TrustMarkTypeUtf8 => "trust_mark_type"u8;

    /// <summary>
    /// <c>trust_mark_type</c> — restricts a <c>federation_list_endpoint</c>
    /// response to subordinates holding a Trust Mark of this type per
    /// Federation §8.2.
    /// </summary>
    public static string TrustMarkType { get; } = Utf8Constants.ToInternedString(TrustMarkTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustMark"/>.</summary>
    public static ReadOnlySpan<byte> TrustMarkUtf8 => "trust_mark"u8;

    /// <summary>
    /// <c>trust_mark</c> — the Trust Mark JWT whose status a requester checks at
    /// the <c>federation_trust_mark_status_endpoint</c> per Federation §8.4. The
    /// REQUIRED form parameter of that endpoint's POST request.
    /// </summary>
    public static string TrustMark { get; } = Utf8Constants.ToInternedString(TrustMarkUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Intermediate"/>.</summary>
    public static ReadOnlySpan<byte> IntermediateUtf8 => "intermediate"u8;

    /// <summary>
    /// <c>intermediate</c> — restricts a <c>federation_list_endpoint</c>
    /// response to subordinates that are (or are not) Intermediate Entities
    /// per Federation §8.2.
    /// </summary>
    public static string Intermediate { get; } = Utf8Constants.ToInternedString(IntermediateUtf8);
}

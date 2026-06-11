using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Well-known HTTP query-parameter NAMES for the OpenID Federation 1.0
/// federation endpoints (§8). These are the <c>?name=value</c> keys a
/// requester places on the URL when calling a
/// <c>federation_fetch_endpoint</c> (§8.1) or
/// <c>federation_list_endpoint</c> (§8.2); the matchers and input builders
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
[DebuggerDisplay("FederationEndpointParameterNames")]
public static class FederationEndpointParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="Sub"/>.</summary>
    public static ReadOnlySpan<byte> SubUtf8 => "sub"u8;

    /// <summary>
    /// <c>sub</c> — the Entity Identifier the requester is asking about at
    /// the <c>federation_fetch_endpoint</c> per Federation §8.1.
    /// </summary>
    public static readonly string Sub = Utf8Constants.ToInternedString(SubUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EntityType"/>.</summary>
    public static ReadOnlySpan<byte> EntityTypeUtf8 => "entity_type"u8;

    /// <summary>
    /// <c>entity_type</c> — restricts a <c>federation_list_endpoint</c>
    /// response to subordinates declaring this Entity Type per
    /// Federation §8.2.
    /// </summary>
    public static readonly string EntityType = Utf8Constants.ToInternedString(EntityTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Anchor"/>.</summary>
    public static ReadOnlySpan<byte> AnchorUtf8 => "anchor"u8;

    /// <summary>
    /// <c>anchor</c> — the Trust Anchor the requester trusts, against which
    /// a <c>federation_resolve_endpoint</c> resolves the subject's chain per
    /// Federation §8.3.
    /// </summary>
    public static readonly string Anchor = Utf8Constants.ToInternedString(AnchorUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Type"/>.</summary>
    public static ReadOnlySpan<byte> TypeUtf8 => "type"u8;

    /// <summary>
    /// <c>type</c> — restricts the metadata a
    /// <c>federation_resolve_endpoint</c> returns to a single Entity Type
    /// per Federation §8.3. Distinct from the §8.2 list endpoint's
    /// <see cref="EntityType"/> parameter — the two endpoints spell the
    /// entity-type filter differently on the wire.
    /// </summary>
    public static readonly string Type = Utf8Constants.ToInternedString(TypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustMarked"/>.</summary>
    public static ReadOnlySpan<byte> TrustMarkedUtf8 => "trust_marked"u8;

    /// <summary>
    /// <c>trust_marked</c> — restricts a <c>federation_list_endpoint</c>
    /// response to subordinates holding at least one Trust Mark per
    /// Federation §8.2.
    /// </summary>
    public static readonly string TrustMarked = Utf8Constants.ToInternedString(TrustMarkedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustMarkType"/>.</summary>
    public static ReadOnlySpan<byte> TrustMarkTypeUtf8 => "trust_mark_type"u8;

    /// <summary>
    /// <c>trust_mark_type</c> — restricts a <c>federation_list_endpoint</c>
    /// response to subordinates holding a Trust Mark of this type per
    /// Federation §8.2.
    /// </summary>
    public static readonly string TrustMarkType = Utf8Constants.ToInternedString(TrustMarkTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Intermediate"/>.</summary>
    public static ReadOnlySpan<byte> IntermediateUtf8 => "intermediate"u8;

    /// <summary>
    /// <c>intermediate</c> — restricts a <c>federation_list_endpoint</c>
    /// response to subordinates that are (or are not) Intermediate Entities
    /// per Federation §8.2.
    /// </summary>
    public static readonly string Intermediate = Utf8Constants.ToInternedString(IntermediateUtf8);
}

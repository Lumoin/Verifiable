using System.Diagnostics;

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
    /// <summary>
    /// <c>sub</c> — the Entity Identifier the requester is asking about at
    /// the <c>federation_fetch_endpoint</c> per Federation §8.1.
    /// </summary>
    public static readonly string Sub = "sub";

    /// <summary>
    /// <c>entity_type</c> — restricts a <c>federation_list_endpoint</c>
    /// response to subordinates declaring this Entity Type per
    /// Federation §8.2.
    /// </summary>
    public static readonly string EntityType = "entity_type";

    /// <summary>
    /// <c>anchor</c> — the Trust Anchor the requester trusts, against which
    /// a <c>federation_resolve_endpoint</c> resolves the subject's chain per
    /// Federation §8.3.
    /// </summary>
    public static readonly string Anchor = "anchor";

    /// <summary>
    /// <c>type</c> — restricts the metadata a
    /// <c>federation_resolve_endpoint</c> returns to a single Entity Type
    /// per Federation §8.3. Distinct from the §8.2 list endpoint's
    /// <see cref="EntityType"/> parameter — the two endpoints spell the
    /// entity-type filter differently on the wire.
    /// </summary>
    public static readonly string Type = "type";

    /// <summary>
    /// <c>trust_marked</c> — restricts a <c>federation_list_endpoint</c>
    /// response to subordinates holding at least one Trust Mark per
    /// Federation §8.2.
    /// </summary>
    public static readonly string TrustMarked = "trust_marked";

    /// <summary>
    /// <c>trust_mark_type</c> — restricts a <c>federation_list_endpoint</c>
    /// response to subordinates holding a Trust Mark of this type per
    /// Federation §8.2.
    /// </summary>
    public static readonly string TrustMarkType = "trust_mark_type";

    /// <summary>
    /// <c>intermediate</c> — restricts a <c>federation_list_endpoint</c>
    /// response to subordinates that are (or are not) Intermediate Entities
    /// per Federation §8.2.
    /// </summary>
    public static readonly string Intermediate = "intermediate";
}

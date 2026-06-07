using System.Collections.Frozen;
using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Application-supplied contribution to the entity's own
/// <c>/.well-known/openid-federation</c> Entity Configuration JWT. The
/// library produces the EC's structural claims (<c>iss</c>, <c>sub</c>,
/// <c>iat</c>, <c>exp</c>, <c>jwks</c>) from the registration's federation
/// identity and signing keys; everything else — per-entity-type metadata
/// blocks, authority hints, and trust marks — comes from this record
/// returned by
/// <see cref="Server.AuthorizationServerIntegration.ContributeFederationMetadataAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// The record's claim shapes are arbitrary nested JSON objects (string keys
/// to primitive / list / nested-dictionary values), encoded into the EC
/// payload by <see cref="EntityStatementJsonBuilder"/> via hand-written
/// <see cref="System.Text.StringBuilder"/> emission. The application is
/// free to compute its metadata blocks with any JSON library; it hands the
/// library typed dictionaries the library then walks.
/// </para>
/// </remarks>
[DebuggerDisplay("FederationEntityConfigurationContribution Metadata={Metadata.Count}")]
public sealed record FederationEntityConfigurationContribution
{
    /// <summary>
    /// Singleton empty contribution. Applications return this when the
    /// EC needs no contributed claims beyond the library-emitted structural
    /// claims.
    /// </summary>
    public static FederationEntityConfigurationContribution Empty { get; } = new();


    /// <summary>
    /// Per-entity-type metadata blocks keyed by
    /// <see cref="EntityTypeIdentifier"/>. Each value is the metadata
    /// document for that entity type (e.g. <c>openid_relying_party</c> →
    /// <c>{ "jwks": {...}, "redirect_uris": [...] }</c>) as a nested
    /// dictionary tree of string keys to JSON-compatible values.
    /// </summary>
    /// <remarks>
    /// Emitted as the EC's <c>metadata</c> top-level claim per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-5.1">Federation §5.1</see>.
    /// When the dictionary is empty, the <c>metadata</c> claim is omitted
    /// entirely.
    /// </remarks>
    public IReadOnlyDictionary<EntityTypeIdentifier, IReadOnlyDictionary<string, object>> Metadata { get; init; } =
        FrozenDictionary<EntityTypeIdentifier, IReadOnlyDictionary<string, object>>.Empty;


    /// <summary>
    /// Authority hints declared by this entity per Federation §3.1 — the
    /// URLs of immediate superiors the entity considers part of its trust
    /// chain. <see langword="null"/> or empty omits the claim entirely.
    /// </summary>
    public IReadOnlyList<Uri>? AuthorityHints { get; init; }


    /// <summary>
    /// Additional top-level claims to merge into the EC payload after the
    /// library's structural claims and the dedicated slots above. Use for
    /// trust marks, <c>crit</c> extensions, or deployment-specific
    /// federation extensions the library does not model individually.
    /// </summary>
    /// <remarks>
    /// Keys collide-by-name with the library's structural claims; the
    /// library's claims take precedence. The application is responsible
    /// for not shadowing required claims.
    /// </remarks>
    public IReadOnlyDictionary<string, object>? AdditionalClaims { get; init; }
}

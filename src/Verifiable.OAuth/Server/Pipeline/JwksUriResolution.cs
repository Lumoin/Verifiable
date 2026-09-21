using Verifiable.Core;
using Verifiable.Core.OutboundFetch;

namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// Why a <see cref="ResolveJwksUriDelegate"/> call ended.
/// </summary>
public enum JwksUriResolutionOutcome
{
    /// <summary>
    /// The key set was fetched and is a well-formed
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5">RFC 7517 §5</see> JWK Set document;
    /// <see cref="JwksUriResolution.Jwks"/> is set.
    /// </summary>
    Resolved = 0,

    /// <summary>
    /// The outbound-fetch policy denied the <c>jwks_uri</c> target (or a redirect hop) before any
    /// terminal response was obtained — the same SSRF-relevant refusal
    /// <see cref="Verifiable.OAuth.Server.Pipeline.ClientIdMetadataResolutionOutcome.PolicyDenied"/>
    /// reports for the enclosing document.
    /// </summary>
    PolicyDenied,

    /// <summary>
    /// The key set could not be fetched: a non-200 status, an unfollowed or excessive redirect chain,
    /// a response exceeding <see cref="JwksUriResolverOptions.MaximumDocumentBytes"/>, or a transport
    /// failure.
    /// </summary>
    FetchFailed,

    /// <summary>
    /// The fetched response was not a usable JWK Set: an unacceptable content type, or a body that is
    /// not a well-formed <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5">RFC 7517 §5</see>
    /// JWK Set document — "The JSON object MUST have a 'keys' member, with its value being an array of
    /// JWKs."
    /// </summary>
    InvalidDocument,

    /// <summary>
    /// The caller's own <see cref="ResolveJwksUriDelegate"/> implementation declined to dial this
    /// <c>jwks_uri</c> under its own retry policy, leaving whatever key material a prior resolution
    /// already provided in place. <see cref="JwksUriResolver.ResolveAsync"/> never produces this
    /// outcome — only an application's own caching implementation of the delegate does.
    /// </summary>
    NotRefreshed
}


/// <summary>
/// The result of a <see cref="ResolveJwksUriDelegate"/> call.
/// </summary>
/// <remarks>
/// Only a <see cref="JwksUriResolutionOutcome.Resolved"/> result carries <see cref="Jwks"/>; every
/// other outcome leaves it <see langword="null"/> and <see cref="Defect"/> carries internal diagnostics
/// for logs and traces — never surface it in a wire response, since the key set is served from a URL
/// the client itself controls.
/// </remarks>
public sealed record JwksUriResolution
{
    /// <summary>Why this resolution ended.</summary>
    public required JwksUriResolutionOutcome Outcome { get; init; }

    /// <summary>
    /// The fetched JWK Set as opaque JSON text when <see cref="Outcome"/> is
    /// <see cref="JwksUriResolutionOutcome.Resolved"/>; otherwise <see langword="null"/>.
    /// </summary>
    public string? Jwks { get; init; }

    /// <summary>
    /// The freshness <see cref="JwksUriResolver.ResolveAsync"/>'s response headers imply, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111 §5.2</see>, when
    /// <see cref="Outcome"/> is <see cref="JwksUriResolutionOutcome.Resolved"/>. Every other outcome
    /// leaves this at its default value — not storable, zero lifetime — so a caller cannot infer a
    /// cacheable lifetime from a fetch that never produced a key set.
    /// </summary>
    public HttpCacheFreshness Freshness { get; init; }

    /// <summary>
    /// Internal diagnostic detail for a non-<see cref="JwksUriResolutionOutcome.Resolved"/> outcome.
    /// For logs and traces only — never surface this text in a wire response.
    /// </summary>
    public string? Defect { get; init; }


    /// <summary>Whether <see cref="Outcome"/> is <see cref="JwksUriResolutionOutcome.Resolved"/>.</summary>
    public bool IsResolved => Outcome == JwksUriResolutionOutcome.Resolved;
}


/// <summary>
/// Resolves a client's JSON Web Key Set from its <c>jwks_uri</c>, per
/// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-2">RFC 7591 §2</see> — "URL string
/// referencing the client's JSON Web Key (JWK) Set [RFC7517] document, which contains the client's
/// public keys."
/// </summary>
/// <remarks>
/// <see cref="JwksUriResolver.ResolveAsync"/> is the library's one attempt: it performs the guarded
/// fetch and the RFC 7517 §5 validation and reports a <see cref="JwksUriResolution"/> together with
/// the <see cref="JwksUriResolution.Freshness"/> its headers imply; only cancellation propagates as an
/// exception. It caches nothing and retains no state between calls — THIS delegate's implementation
/// is the caching layer. It owns the store, honours
/// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111 §5.2</see>'s freshness
/// calculation and <see href="https://www.rfc-editor.org/rfc/rfc9111#section-4.2.4">RFC 9111 §4.2.4</see>'s
/// "A cache MUST NOT generate a stale response unless it is disconnected or doing so is explicitly
/// permitted by the client or origin server," and decides what follows a failure. It is asked on
/// every resolution — including by a caller serving a cached enclosing Client ID Metadata Document
/// through <see cref="ClientIdMetadataDocuments.RefreshJwksAsync"/> — so an implementation that does
/// not bound its own retries after a failure puts one outbound request on a host the client itself
/// names for every authorization request that reaches it. Consumed by
/// <see cref="ClientIdMetadataDocuments.ResolveAsync"/> for a <c>private_key_jwt</c> Client ID
/// Metadata Document client whose document names a <c>jwks_uri</c> instead of an inline <c>jwks</c>,
/// and wireable to
/// <see cref="Verifiable.OAuth.Server.PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,ResolveJwksUriDelegate?)"/>
/// for an RFC 7591-registered client whose <see cref="ClientRecord.ClientJwksUri"/> was never
/// dereferenced at registration time.
/// </remarks>
/// <param name="jwksUri">The client's <c>jwks_uri</c> to fetch the key set from.</param>
/// <param name="context">
/// The per-request context; the guarded fetch reads its
/// <see cref="Verifiable.Core.OutboundFetch.OutboundFetchPolicy"/> from here.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<JwksUriResolution> ResolveJwksUriDelegate(
    Uri jwksUri,
    ExchangeContext context,
    CancellationToken cancellationToken);

using Verifiable.Core;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Resolves the AS metadata for a given issuer, fetching and parsing the
/// <c>/.well-known/oauth-authorization-server</c> or
/// <c>/.well-known/openid-configuration</c> document on first use and
/// reporting a typed <see cref="AuthorizationServerMetadataResolution"/>.
/// </summary>
/// <remarks>
/// <para>
/// The library does not pick a fetch strategy or a caching policy — that stands.
/// <see cref="Verifiable.OAuth.Client.AuthorizationServerMetadataDocuments.ResolveAsync"/> is the
/// library's one attempt: the guarded fetch, RFC 8414 §3's well-known URL computation, the §3.2
/// content-type and status checks, the §3.3 issuer match, and the RFC 9111 §5.2 freshness the
/// response headers imply, reported alongside the typed outcome. It caches nothing and retains no
/// state between calls.
/// </para>
/// <para>
/// The implementation of THIS delegate is the caching layer: it composes the attempt above, owns the
/// store (a process dictionary, a distributed cache, a grain), honours
/// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111 §5.2</see>'s freshness
/// calculation and
/// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-4.2.4">RFC 9111 §4.2.4</see>'s "A cache
/// MUST NOT generate a stale response unless it is disconnected or doing so is explicitly permitted
/// by the client or origin server," and decides what follows a failed attempt — retry, hold, or
/// serving a previously cached record subject to that §4.2.4 permission.
/// </para>
/// <para>
/// Every caller-visible failure is a value on the returned
/// <see cref="AuthorizationServerMetadataResolution"/>, never an exception — only cancellation
/// propagates — the same contract <see cref="Verifiable.OAuth.Server.ResolveClientMetadataDelegate"/>
/// and <see cref="Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate"/> state for their own
/// resolutions.
/// </para>
/// <para>
/// Tests wire an in-process resolver that returns a pre-built, resolved
/// <see cref="AuthorizationServerMetadataResolution"/> without any HTTP at all,
/// exactly as an application developer would when running against a stub
/// AS.
/// </para>
/// </remarks>
/// <param name="issuer">The AS issuer URL to resolve.</param>
/// <param name="context">
/// The per-call exchange context. Carried so the implementation can make
/// per-call decisions from request-scoped data — capability/functionality
/// gating, and the outbound-fetch (SSRF) policy that governs which
/// <paramref name="issuer"/>-derived metadata URLs may be contacted.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The resolution.</returns>
public delegate ValueTask<AuthorizationServerMetadataResolution> ResolveAuthorizationServerMetadataDelegate(
    Uri issuer,
    ExchangeContext context,
    CancellationToken cancellationToken);

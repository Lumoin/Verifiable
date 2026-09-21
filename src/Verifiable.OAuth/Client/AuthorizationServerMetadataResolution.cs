using Verifiable.Core.OutboundFetch;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Why a <see cref="ResolveAuthorizationServerMetadataDelegate"/> call ended.
/// </summary>
public enum AuthorizationServerMetadataResolutionOutcome
{
    /// <summary>
    /// The document was fetched, parsed, and its issuer matched the identifier the metadata URL was
    /// derived from; <see cref="AuthorizationServerMetadataResolution.Metadata"/> is set.
    /// </summary>
    Resolved = 0,

    /// <summary>
    /// The issuer identifier supplied to <see cref="AuthorizationServerMetadataDocuments.ResolveAsync"/>
    /// fails <see href="https://www.rfc-editor.org/rfc/rfc8414#section-2">RFC 8414 §2</see>'s shape
    /// rule before any network contact — not an absolute <c>https</c> URL, or carrying a query or
    /// fragment component.
    /// </summary>
    InvalidIssuer,

    /// <summary>
    /// The outbound-fetch policy denied the target (or a redirect hop) before any terminal response
    /// was obtained — an SSRF-relevant refusal.
    /// </summary>
    PolicyDenied,

    /// <summary>
    /// The document could not be fetched: a non-200 status, an unfollowed or excessive redirect
    /// chain, an oversized response, or a transport failure.
    /// </summary>
    FetchFailed,

    /// <summary>
    /// The fetched response was not a usable authorization server metadata document: an unacceptable
    /// content type, or a body <see cref="Verifiable.OAuth.OAuthResponseParsers.ParseAuthorizationServerMetadata"/>
    /// refused.
    /// </summary>
    InvalidDocument,

    /// <summary>
    /// The document parsed, but its <c>issuer</c> member did not match the issuer identifier the
    /// metadata URL was derived from — <see href="https://www.rfc-editor.org/rfc/rfc8414#section-3.3">
    /// RFC 8414 §3.3</see>: "If these values are not identical, the data contained in the response
    /// MUST NOT be used." A distinct outcome from <see cref="InvalidDocument"/> because the document
    /// itself is well-formed; only its trustworthiness for THIS issuer failed.
    /// </summary>
    IssuerMismatch
}


/// <summary>
/// The result of a <see cref="ResolveAuthorizationServerMetadataDelegate"/> call.
/// </summary>
/// <remarks>
/// Only a <see cref="AuthorizationServerMetadataResolutionOutcome.Resolved"/> result carries
/// <see cref="Metadata"/>; every other outcome leaves it <see langword="null"/> and
/// <see cref="Defect"/> carries internal diagnostics for logs and traces — never surface it in a
/// wire response, since the document is served from a URL the authorization server itself controls.
/// </remarks>
public sealed record AuthorizationServerMetadataResolution
{
    /// <summary>Why this resolution ended.</summary>
    public required AuthorizationServerMetadataResolutionOutcome Outcome { get; init; }

    /// <summary>
    /// The parsed, issuer-matched metadata when <see cref="Outcome"/> is
    /// <see cref="AuthorizationServerMetadataResolutionOutcome.Resolved"/>; otherwise <see langword="null"/>.
    /// </summary>
    public AuthorizationServerMetadata? Metadata { get; init; }

    /// <summary>
    /// Internal diagnostic detail for a non-<see cref="AuthorizationServerMetadataResolutionOutcome.Resolved"/>
    /// outcome. For logs and traces only — never surface this text in a wire response.
    /// </summary>
    public string? Defect { get; init; }

    /// <summary>
    /// The freshness <see cref="AuthorizationServerMetadataDocuments.ResolveAsync"/>'s document
    /// response headers imply, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111 §5.2</see>, when
    /// <see cref="Outcome"/> is <see cref="AuthorizationServerMetadataResolutionOutcome.Resolved"/>.
    /// Every other outcome leaves this at its default value — not storable, zero lifetime — so a
    /// caller cannot infer a cacheable lifetime from a fetch that never produced a trustworthy
    /// document.
    /// </summary>
    public HttpCacheFreshness Freshness { get; init; }


    /// <summary>Whether <see cref="Outcome"/> is <see cref="AuthorizationServerMetadataResolutionOutcome.Resolved"/>.</summary>
    public bool IsResolved => Outcome == AuthorizationServerMetadataResolutionOutcome.Resolved;
}

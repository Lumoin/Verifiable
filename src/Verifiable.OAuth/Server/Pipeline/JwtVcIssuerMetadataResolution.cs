using Verifiable.Core.OutboundFetch;

namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// Why a <see cref="JwtVcIssuerMetadataDocuments.ResolveAsync"/> call ended.
/// </summary>
public enum JwtVcIssuerMetadataResolutionOutcome
{
    /// <summary>
    /// The document was fetched and its <c>issuer</c> member matched the <c>iss</c> value the metadata
    /// URL was derived from; <see cref="JwtVcIssuerMetadataResolution.Jwks"/> or
    /// <see cref="JwtVcIssuerMetadataResolution.JwksUri"/> is set.
    /// </summary>
    Resolved = 0,

    /// <summary>
    /// SD-JWT VC draft-19, Section 4: "The iss MUST be a case-sensitive URL using the HTTPS scheme
    /// that contains scheme, host and, optionally, port number and path components as defined in
    /// [RFC3986], but no query or fragment components." A shape defect here never contacts the
    /// network, mirroring <see cref="Verifiable.OAuth.Client.AuthorizationServerMetadataResolutionOutcome.InvalidIssuer"/>.
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
    /// The fetched response was not a usable JWT VC Issuer Metadata configuration: an unacceptable
    /// content type, a body that is not well-formed JSON, or a body that carries neither or both of
    /// <c>jwks</c> and <c>jwks_uri</c> — SD-JWT VC draft-19 §4.2's "MUST include either
    /// <c>jwks_uri</c> or <c>jwks</c> in their JWT VC Issuer Metadata, but not both."
    /// </summary>
    InvalidDocument,

    /// <summary>
    /// SD-JWT VC draft-19 §4.3: "The issuer value returned MUST be identical to the iss value of the
    /// Issuer-signed JWT. If these values are not identical, the data contained in the response MUST
    /// NOT be used." Includes a document that carries no <c>issuer</c> member at all.
    /// </summary>
    IssuerMismatch
}


/// <summary>
/// The result of a <see cref="JwtVcIssuerMetadataDocuments.ResolveAsync"/> call.
/// </summary>
/// <remarks>
/// Only a <see cref="JwtVcIssuerMetadataResolutionOutcome.Resolved"/> result carries
/// <see cref="Jwks"/> or <see cref="JwksUri"/>; every other outcome leaves both
/// <see langword="null"/> and <see cref="Defect"/> carries internal diagnostics for logs and traces —
/// never surface it in a wire response, since the document is served from a URL the credential's own
/// <c>iss</c> claim names.
/// </remarks>
public sealed record JwtVcIssuerMetadataResolution
{
    /// <summary>Why this resolution ended.</summary>
    public required JwtVcIssuerMetadataResolutionOutcome Outcome { get; init; }

    /// <summary>
    /// The document's <c>issuer</c> member value, when the document was parsed far enough to extract
    /// one. Set even for an <see cref="JwtVcIssuerMetadataResolutionOutcome.IssuerMismatch"/> result
    /// so a caller can log which identity the document claimed.
    /// </summary>
    public string? Issuer { get; init; }

    /// <summary>
    /// The document's inline <c>jwks</c> member, re-rendered as JWK Set JSON text, when
    /// <see cref="Outcome"/> is <see cref="JwtVcIssuerMetadataResolutionOutcome.Resolved"/> and the
    /// document carried <c>jwks</c> rather than <c>jwks_uri</c>; otherwise <see langword="null"/>.
    /// </summary>
    public string? Jwks { get; init; }

    /// <summary>
    /// The document's <c>jwks_uri</c> member, when <see cref="Outcome"/> is
    /// <see cref="JwtVcIssuerMetadataResolutionOutcome.Resolved"/> and the document carried
    /// <c>jwks_uri</c> rather than an inline <c>jwks</c>; otherwise <see langword="null"/>.
    /// </summary>
    public Uri? JwksUri { get; init; }

    /// <summary>
    /// The freshness <see cref="JwtVcIssuerMetadataDocuments.ResolveAsync"/>'s document response
    /// headers imply, per <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111
    /// §5.2</see>, when <see cref="Outcome"/> is <see cref="JwtVcIssuerMetadataResolutionOutcome.Resolved"/>.
    /// Every other outcome leaves this at its default value — not storable, zero lifetime — so a
    /// caller cannot infer a cacheable lifetime from a fetch that never produced a document.
    /// </summary>
    public HttpCacheFreshness Freshness { get; init; }

    /// <summary>
    /// Internal diagnostic detail for a non-<see cref="JwtVcIssuerMetadataResolutionOutcome.Resolved"/>
    /// outcome. For logs and traces only — never surface this text in a wire response.
    /// </summary>
    public string? Defect { get; init; }


    /// <summary>Whether <see cref="Outcome"/> is <see cref="JwtVcIssuerMetadataResolutionOutcome.Resolved"/>.</summary>
    public bool IsResolved => Outcome == JwtVcIssuerMetadataResolutionOutcome.Resolved;
}

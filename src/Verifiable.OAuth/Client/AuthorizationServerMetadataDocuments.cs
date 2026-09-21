using System.Text;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.JCose;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Performs the library's one authorization server metadata attempt: the fetch-validate pipeline
/// per <see href="https://www.rfc-editor.org/rfc/rfc8414#section-3">RFC 8414 §3</see>. It performs
/// no caching and retains no state between calls — see
/// <see cref="ResolveAuthorizationServerMetadataDelegate"/> for why that is the calling
/// application's concern, not this library's.
/// </summary>
public static class AuthorizationServerMetadataDocuments
{
    /// <summary>
    /// Fetches, validates, and issuer-matches an authorization server's metadata document through
    /// the guarded <see cref="OutboundFetch"/> chokepoint.
    /// </summary>
    /// <param name="issuer">
    /// The authorization server's issuer identifier per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-2">RFC 8414 §2</see> — a URL that
    /// uses the <c>https</c> scheme and has no query or fragment components.
    /// </param>
    /// <param name="wellKnownPath">
    /// The <see cref="WellKnownPath"/> the metadata URL is computed from — the application's choice
    /// of which well-known suffix it uses, per RFC 8414 §3's "An OAuth 2.0 application using this
    /// specification MUST specify what well-known URI suffix it will use for this purpose."
    /// Typically <see cref="WellKnownPaths.OAuthAuthorizationServer"/>.
    /// </param>
    /// <param name="context">
    /// The per-request context; the guarded fetch reads its
    /// <see cref="Verifiable.Core.OutboundFetch.OutboundFetchPolicy"/> from here.
    /// </param>
    /// <param name="transport">
    /// The application-supplied single-hop transport the guarded fetch drives.
    /// <see cref="Verifiable.OAuth"/> takes no <c>System.Net.Http</c> dependency, so the network
    /// primitive is injected.
    /// </param>
    /// <param name="options">The resolver's byte cap.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The typed outcome and, for a <see cref="AuthorizationServerMetadataResolutionOutcome.Resolved"/>
    /// answer, the <see cref="HttpCacheFreshness"/> the document response headers imply. Every other
    /// outcome leaves <see cref="AuthorizationServerMetadataResolution.Freshness"/> at its default
    /// value, which reports nothing storable — storing a resolved document, and deciding what
    /// follows a failure, is the caller's own <see cref="ResolveAuthorizationServerMetadataDelegate"/>
    /// implementation's concern.
    /// </returns>
    public static async ValueTask<AuthorizationServerMetadataResolution> ResolveAsync(
        Uri issuer,
        WellKnownPath wellKnownPath,
        ExchangeContext context,
        OutboundTransportDelegate transport,
        AuthorizationServerMetadataResolverOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(wellKnownPath);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(options);

        //RFC 8414 §2: "REQUIRED. The authorization server's issuer identifier, which is a URL that
        //uses the 'https' scheme and has no query or fragment components." A MUST-tier shape defect
        //never contacts the network, mirroring ClientIdMetadataDocuments.ResolveAsync's Step 1.
        if(!issuer.IsAbsoluteUri
            || !string.Equals(issuer.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
            || !string.IsNullOrEmpty(issuer.Query)
            || !string.IsNullOrEmpty(issuer.Fragment))
        {
            return new AuthorizationServerMetadataResolution
            {
                Outcome = AuthorizationServerMetadataResolutionOutcome.InvalidIssuer,
                Defect = "The issuer identifier is not an absolute https URL, or carries a query or fragment component."
            };
        }

        Uri metadataUri = wellKnownPath.ComputeUri(issuer.OriginalString);

        OutboundRequest request = new()
        {
            Target = metadataUri,
            Method = "GET",
            MaxResponseBytes = options.MaximumDocumentBytes
        };

        OutboundFetchResult fetch;
        try
        {
            fetch = await Verifiable.Core.OutboundFetch.OutboundFetch.FetchAsync(
                request, context, transport, cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return new AuthorizationServerMetadataResolution
            {
                Outcome = AuthorizationServerMetadataResolutionOutcome.FetchFailed,
                Defect = "Transport failure while fetching the authorization server metadata document."
            };
        }

        if(!fetch.IsFetched || fetch.Response is null)
        {
            return new AuthorizationServerMetadataResolution
            {
                Outcome = fetch.Outcome == OutboundFetchOutcome.DeniedByPolicy
                    ? AuthorizationServerMetadataResolutionOutcome.PolicyDenied
                    : AuthorizationServerMetadataResolutionOutcome.FetchFailed,
                Defect = fetch.DenyReason
            };
        }

        OutboundResponse response = fetch.Response;

        //RFC 8414 §3.2: "A successful response MUST use the 200 OK HTTP status code."
        if(response.StatusCode != 200)
        {
            return new AuthorizationServerMetadataResolution
            {
                Outcome = AuthorizationServerMetadataResolutionOutcome.FetchFailed,
                Defect = $"The document fetch returned HTTP status {response.StatusCode}."
            };
        }

        //RFC 8414 §3.2: "return a JSON object using the 'application/json' content type" — exactly
        //that media type, unlike a CIMD or JWKS fetch's +json structured-suffix allowance.
        _ = response.Headers.TryGetValue(WellKnownHttpHeaderNames.ContentType, out string? contentType);
        if(!IsAcceptableContentType(contentType))
        {
            return new AuthorizationServerMetadataResolution
            {
                Outcome = AuthorizationServerMetadataResolutionOutcome.InvalidDocument,
                Defect = $"The document content type '{contentType}' is not application/json."
            };
        }

        //The authoritative post-read size check — MaxResponseBytes above is only a transport hint a
        //hostile or non-conforming transport may not honor.
        if(response.Body.Length > options.MaximumDocumentBytes)
        {
            return new AuthorizationServerMetadataResolution
            {
                Outcome = AuthorizationServerMetadataResolutionOutcome.FetchFailed,
                Defect = "The document exceeds the configured maximum size."
            };
        }

        HttpResponseData responseData = new()
        {
            Body = Encoding.UTF8.GetString(response.Body.Span),
            StatusCode = response.StatusCode
        };

        Result<AuthorizationServerMetadata, OAuthParseError> parsed =
            OAuthResponseParsers.ParseAuthorizationServerMetadata(responseData);
        if(!parsed.IsSuccess)
        {
            return new AuthorizationServerMetadataResolution
            {
                Outcome = AuthorizationServerMetadataResolutionOutcome.InvalidDocument,
                Defect = $"The document has conformance defects: {parsed.Error}."
            };
        }

        AuthorizationServerMetadata metadata = parsed.Value;

        //RFC 8414 §3.3: "The 'issuer' value returned MUST be identical to the authorization server's
        //issuer identifier value into which the well-known URI string was inserted to create the URL
        //used to retrieve the metadata. If these values are not identical, the data contained in the
        //response MUST NOT be used." A distinct outcome from InvalidDocument — the document itself
        //parsed cleanly; only its trustworthiness for THIS issuer failed.
        if(!AuthorizationServerMetadataValidation.IsIssuerMatch(metadata, issuer))
        {
            return new AuthorizationServerMetadataResolution
            {
                Outcome = AuthorizationServerMetadataResolutionOutcome.IssuerMismatch,
                Defect = "The document's issuer does not match the issuer identifier the metadata URL was derived from."
            };
        }

        return new AuthorizationServerMetadataResolution
        {
            Outcome = AuthorizationServerMetadataResolutionOutcome.Resolved,
            Metadata = metadata,
            Freshness = HttpCacheFreshness.Compute(response)
        };
    }


    /// <summary>
    /// Whether <paramref name="contentType"/> is exactly <c>application/json</c> per RFC 8414 §3.2 —
    /// no <c>+json</c> structured-suffix allowance, unlike <c>ClientIdMetadataDocuments</c>'s and
    /// <c>JwksUriResolver</c>'s content-type gate. Parameters (e.g. <c>;charset=utf-8</c>) are
    /// stripped before comparison.
    /// </summary>
    private static bool IsAcceptableContentType(string? contentType)
    {
        return ContentTypeReader.ReadMediaType(contentType).Equals(
            WellKnownMediaTypes.Application.Json, StringComparison.OrdinalIgnoreCase);
    }
}

using Verifiable.Core;
using Verifiable.Core.Outbound;
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
    /// <see cref="Verifiable.Core.Outbound.OutboundFetchPolicy"/> from here.
    /// </param>
    /// <param name="transport">
    /// The application-supplied single-hop transport the guarded fetch drives.
    /// <see cref="Verifiable.OAuth"/> takes no <c>System.Net.Http</c> dependency, so the network
    /// primitive is injected.
    /// </param>
    /// <param name="parseDocument">The complete-document parser supplied by the serialization adapter.</param>
    /// <param name="options">The resolver's byte cap.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A closed outcome carrying its evidence. Only a resolved document carries cache freshness;
    /// storage and retry decisions belong to the caller's resolver implementation.
    /// </returns>
    public static async ValueTask<AuthorizationServerMetadataResolution> ResolveAsync(
        Uri issuer,
        WellKnownPath wellKnownPath,
        ExchangeContext context,
        OutboundTransportDelegate transport,
        ParseAuthorizationServerMetadataDelegate parseDocument,
        AuthorizationServerMetadataResolverOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(wellKnownPath);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(parseDocument);
        ArgumentNullException.ThrowIfNull(options);

        //RFC 8414 §2: "REQUIRED. The authorization server's issuer identifier, which is a URL that
        //uses the 'https' scheme and has no query or fragment components." A MUST-tier shape defect
        //never contacts the network, mirroring ClientIdMetadataDocuments.ResolveAsync's Step 1.
        Result<IssuerIdentifier, IssuerIdentifierFault> expectedIssuer = IssuerIdentifier.Parse(issuer.OriginalString);
        if(!expectedIssuer.IsSuccess)
        {
            return new AuthorizationServerMetadataInvalidIssuer { Issuer = issuer };
        }

        Uri metadataUri = wellKnownPath.ComputeUri(issuer.OriginalString);

        OutboundRequest request = new()
        {
            Target = metadataUri,
            Method = WellKnownHttpMethods.Get,
            MaxResponseBytes = options.MaximumDocumentBytes
        };

        OutboundFetchResult fetch;
        try
        {
            fetch = await Verifiable.Core.Outbound.OutboundFetch.FetchAsync(
                request, context, transport, cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch(Exception exception)
        {
            return new AuthorizationServerMetadataUnreachable { FailureKind = exception.GetType() };
        }

        if(fetch.RefusedRedirect is OutboundRedirectRefusal redirect)
        {
            return new AuthorizationServerMetadataRedirectRefused
            {
                StatusCode = redirect.StatusCode,
                Location = redirect.Location
            };
        }

        if(!fetch.IsFetched || fetch.Response is null)
        {
            return new AuthorizationServerMetadataPolicyDenied { Target = fetch.FinalUri };
        }

        OutboundResponse response = fetch.Response;

        //RFC 8414 §3.2: "A successful response MUST use the 200 OK HTTP status code."
        if(response.StatusCode != 200)
        {
            return new AuthorizationServerMetadataNotAnswered { StatusCode = response.StatusCode };
        }

        //RFC 8414 §3.2: "return a JSON object using the 'application/json' content type" — exactly
        //that media type, unlike a CIMD or JWKS fetch's +json structured-suffix allowance.
        _ = response.Headers.TryGetValue(WellKnownHttpHeaderNames.ContentType, out string? contentType);
        if(!IsAcceptableContentType(contentType))
        {
            return new AuthorizationServerMetadataUnsupportedMediaType { ContentType = contentType };
        }

        //The authoritative post-read size check — MaxResponseBytes above is only a transport hint a
        //hostile or non-conforming transport may not honor.
        if(response.Body.Length > options.MaximumDocumentBytes)
        {
            return new AuthorizationServerMetadataTooLarge
            {
                Limit = options.MaximumDocumentBytes,
                LengthSeen = response.Body.Length
            };
        }

        Result<AuthorizationServerMetadata, AuthorizationServerMetadataParseError> parsed =
            parseDocument(response.Body.Memory);
        if(!parsed.IsSuccess)
        {
            return new AuthorizationServerMetadataUnreadable { Error = parsed.Error };
        }

        AuthorizationServerMetadata metadata = parsed.Value;

        //RFC 8414 §3.3: "The 'issuer' value returned MUST be identical to the authorization server's
        //issuer identifier value into which the well-known URI string was inserted to create the URL
        //used to retrieve the metadata. If these values are not identical, the data contained in the
        //response MUST NOT be used." A distinct outcome from Unreadable — the document itself
        //parsed cleanly; only its trustworthiness for THIS issuer failed.
        Result<IssuerIdentifier, IssuerIdentifierFault> publishedIssuer = IssuerIdentifier.Parse(metadata.Issuer.OriginalString);
        if(!publishedIssuer.IsSuccess || publishedIssuer.Value != expectedIssuer.Value)
        {
            return new AuthorizationServerMetadataIssuerMismatch
            {
                RequestedIssuer = issuer,
                PublishedIssuer = metadata.Issuer.OriginalString,
                MetadataLocation = fetch.FinalUri
            };
        }

        return new AuthorizationServerMetadataResolved
        {
            MetadataLocation = fetch.FinalUri,
            Metadata = metadata,
            Freshness = HttpCacheFreshness.Compute(response)
        };
    }


    /// <summary>
    /// Resolves an OpenID Provider's metadata: at its OpenID Connect discovery location first
    /// (<see href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">OpenID Connect Discovery 1.0
    /// §4</see>, <see cref="WellKnownPaths.OpenIdConfiguration"/>), then, where that answers no document whose issuer is the
    /// one asked for, at its RFC 8414 location (<see cref="WellKnownPaths.OAuthAuthorizationServer"/>; RFC 8414 §5: "an OAuth
    /// 2.0 authorization server ... may also publish its metadata" at the OpenID location, and a client "using this specification
    /// ... MUST specify what well-known URI suffix it will use"), each attempt <see cref="ResolveAsync"/> with every rule it holds.
    /// The first resolved document is answered. Where neither location resolves one, the RFC 8414 attempt's outcome is answered,
    /// unless that location answered no document at all (<see cref="AuthorizationServerMetadataNotAnswered"/>): then what the
    /// discovery location answered is, a document naming another issuer (<see cref="AuthorizationServerMetadataIssuerMismatch"/>)
    /// among it, since that says more of the provider than a location it never served.
    /// </summary>
    /// <param name="issuer">The provider's issuer identifier.</param>
    /// <param name="context">The per-request context carrying the outbound-fetch policy.</param>
    /// <param name="transport">The application-supplied single-hop transport.</param>
    /// <param name="parseDocument">The complete-document parser supplied by the serialization adapter.</param>
    /// <param name="options">The resolver's byte cap.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The resolution.</returns>
    public static async ValueTask<AuthorizationServerMetadataResolution> ResolveOpenIdProviderAsync(
        Uri issuer,
        ExchangeContext context,
        OutboundTransportDelegate transport,
        ParseAuthorizationServerMetadataDelegate parseDocument,
        AuthorizationServerMetadataResolverOptions options,
        CancellationToken cancellationToken)
    {
        var discovered = await ResolveAsync(
            issuer, WellKnownPaths.OpenIdConfiguration, context, transport, parseDocument, options, cancellationToken).ConfigureAwait(false);

        if(discovered is AuthorizationServerMetadataResolved)
        {
            return discovered;
        }

        var located = await ResolveAsync(
            issuer, WellKnownPaths.OAuthAuthorizationServer, context, transport, parseDocument, options, cancellationToken).ConfigureAwait(false);

        return located is AuthorizationServerMetadataNotAnswered ? discovered : located;
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

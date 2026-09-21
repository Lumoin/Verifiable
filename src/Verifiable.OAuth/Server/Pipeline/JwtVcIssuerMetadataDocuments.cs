using System.Buffers;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Federation;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// Performs the library's one JWT VC Issuer Metadata attempt: the fetch-validate pipeline per
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-19#section-4">SD-JWT VC
/// draft-19, Section 4</see>, plus the key-selection helper an application composes over its result.
/// It performs no caching and retains no state between calls — the application's own
/// <see cref="Verifiable.OAuth.Oid4Vp.Server.ResolveIssuerKeyDelegate"/> implementation is the caching
/// layer, exactly as for <see cref="ClientIdMetadataDocuments"/> and <see cref="JwksUriResolver"/>.
/// </summary>
public static class JwtVcIssuerMetadataDocuments
{

    /// <summary>
    /// Fetches and validates an issuer's JWT VC Issuer Metadata configuration through the guarded
    /// <see cref="OutboundFetch"/> chokepoint.
    /// </summary>
    /// <param name="issuer">The <c>iss</c> value the JWT VC Issuer Metadata URL is derived from.</param>
    /// <param name="context">
    /// The per-request context; the guarded fetch reads its
    /// <see cref="Verifiable.Core.Outbound.OutboundFetchPolicy"/> from here.
    /// </param>
    /// <param name="transport">
    /// The application-supplied single-hop transport the guarded fetch drives.
    /// <see cref="Verifiable.OAuth"/> takes no <c>System.Net.Http</c> dependency, so the network
    /// primitive is injected.
    /// </param>
    /// <param name="options">The resolver's byte cap.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The typed outcome and, for a <see cref="JwtVcIssuerMetadataResolutionOutcome.Resolved"/>
    /// answer, the <see cref="HttpCacheFreshness"/> the document response headers imply. Every other
    /// outcome leaves <see cref="JwtVcIssuerMetadataResolution.Freshness"/> at its default value,
    /// which reports nothing storable — storing a resolved document is the caller's own
    /// <see cref="Verifiable.OAuth.Oid4Vp.Server.ResolveIssuerKeyDelegate"/> implementation's concern.
    /// </returns>
    public static async ValueTask<JwtVcIssuerMetadataResolution> ResolveAsync(
        Uri issuer,
        ExchangeContext context,
        OutboundTransportDelegate transport,
        JwtVcIssuerMetadataDocumentResolverOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(options);

        //§4: "The iss MUST be a case-sensitive URL using the HTTPS scheme that contains scheme, host
        //and, optionally, port number and path components as defined in [RFC3986], but no query or
        //fragment components." A shape defect here never contacts the network, mirroring
        //AuthorizationServerMetadataDocuments.ResolveAsync's own pre-fetch shape check.
        if(!issuer.IsAbsoluteUri
            || !string.Equals(issuer.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
            || !string.IsNullOrEmpty(issuer.Query)
            || !string.IsNullOrEmpty(issuer.Fragment))
        {
            return new JwtVcIssuerMetadataResolution
            {
                Outcome = JwtVcIssuerMetadataResolutionOutcome.InvalidIssuer,
                Defect = "The issuer identifier is not an HTTPS URL, or carries a query or fragment component."
            };
        }

        Uri metadataUri = WellKnownPaths.JwtVcIssuer.ComputeUri(issuer.OriginalString);

        OutboundRequest request = new()
        {
            Target = metadataUri,
            Method = "GET",
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
        catch
        {
            return new JwtVcIssuerMetadataResolution
            {
                Outcome = JwtVcIssuerMetadataResolutionOutcome.FetchFailed,
                Defect = "Transport failure while fetching the JWT VC Issuer Metadata."
            };
        }

        if(!fetch.IsFetched || fetch.Response is null)
        {
            return new JwtVcIssuerMetadataResolution
            {
                Outcome = fetch.Outcome == OutboundFetchOutcome.DeniedByPolicy
                    ? JwtVcIssuerMetadataResolutionOutcome.PolicyDenied
                    : JwtVcIssuerMetadataResolutionOutcome.FetchFailed,
                Defect = fetch.DenyReason
            };
        }

        OutboundResponse response = fetch.Response;

        //§4.2: "A successful response carries a representation of the JWT VC Issuer Metadata
        //configuration as its content, using the application/json media type."
        if(response.StatusCode != 200)
        {
            return new JwtVcIssuerMetadataResolution
            {
                Outcome = JwtVcIssuerMetadataResolutionOutcome.FetchFailed,
                Defect = $"The JWT VC Issuer Metadata fetch returned HTTP status {response.StatusCode}."
            };
        }

        _ = response.Headers.TryGetValue(WellKnownHttpHeaderNames.ContentType, out string? contentType);
        if(!IsApplicationJson(contentType))
        {
            return new JwtVcIssuerMetadataResolution
            {
                Outcome = JwtVcIssuerMetadataResolutionOutcome.InvalidDocument,
                Defect = $"The document content type '{contentType}' is not application/json."
            };
        }

        if(response.Body.Length > options.MaximumDocumentBytes)
        {
            return new JwtVcIssuerMetadataResolution
            {
                Outcome = JwtVcIssuerMetadataResolutionOutcome.FetchFailed,
                Defect = "The JWT VC Issuer Metadata document exceeds the configured maximum size."
            };
        }

        ReadOnlySpan<byte> body = response.Body.Span;
        if(!JwkJsonReader.IsWellFormedJsonDocument(body))
        {
            return new JwtVcIssuerMetadataResolution
            {
                Outcome = JwtVcIssuerMetadataResolutionOutcome.InvalidDocument,
                Defect = "The JWT VC Issuer Metadata document is not well-formed JSON."
            };
        }

        string? documentIssuer = JwkJsonReader.ExtractStringValue(body, AuthorizationServerMetadataParameterNames.IssuerUtf8);

        //§4.3: "The issuer value returned MUST be identical to the iss value of the Issuer-signed
        //JWT. If these values are not identical, the data contained in the response MUST NOT be
        //used." Reuses the code-point-by-code-point comparison RFC 8414 §3.3 metadata already applies.
        if(!AuthorizationServerMetadataValidation.IsIssuerIdentifierMatch(documentIssuer ?? string.Empty, issuer)
            || documentIssuer is null)
        {
            return new JwtVcIssuerMetadataResolution
            {
                Outcome = JwtVcIssuerMetadataResolutionOutcome.IssuerMismatch,
                Issuer = documentIssuer,
                Defect = "The document's issuer does not match the iss value it was derived from."
            };
        }

        bool hasJwks = JwkJsonReader.ContainsKey(body, ClientMetadataParameterNames.JwksUtf8);
        bool hasJwksUri = JwkJsonReader.ContainsKey(body, ClientMetadataParameterNames.JwksUriUtf8);

        //§4.2: "JWT VC Issuer Metadata MUST include either jwks_uri or jwks in their JWT VC Issuer
        //Metadata, but not both."
        if(hasJwks == hasJwksUri)
        {
            return new JwtVcIssuerMetadataResolution
            {
                Outcome = JwtVcIssuerMetadataResolutionOutcome.InvalidDocument,
                Issuer = documentIssuer,
                Defect = hasJwks
                    ? "The document carries both 'jwks' and 'jwks_uri'."
                    : "The document carries neither 'jwks' nor 'jwks_uri'."
            };
        }

        string? jwks = null;
        Uri? jwksUri = null;
        if(hasJwks)
        {
            //ExtractObjectAsString includes the outer braces, so the result is the self-contained
            //JWK Set object JwkJsonReader.SelectKeyByKeyId/SelectSoleKey can scan directly — unlike
            //ExtractObjectContent's brace-exclusive span, which is not itself well-formed JSON.
            jwks = JwkJsonReader.ExtractObjectAsString(body, ClientMetadataParameterNames.JwksUtf8);
        }
        else
        {
            string? jwksUriValue = JwkJsonReader.ExtractStringValue(body, ClientMetadataParameterNames.JwksUriUtf8);
            if(jwksUriValue is null || !Uri.TryCreate(jwksUriValue, UriKind.Absolute, out jwksUri))
            {
                return new JwtVcIssuerMetadataResolution
                {
                    Outcome = JwtVcIssuerMetadataResolutionOutcome.InvalidDocument,
                    Issuer = documentIssuer,
                    Defect = "The document's 'jwks_uri' is not a valid absolute URI."
                };
            }
        }

        return new JwtVcIssuerMetadataResolution
        {
            Outcome = JwtVcIssuerMetadataResolutionOutcome.Resolved,
            Issuer = documentIssuer,
            Jwks = jwks,
            JwksUri = jwksUri,
            Freshness = HttpCacheFreshness.Compute(response)
        };
    }


    /// <summary>
    /// Selects the issuer's verification key from a <see cref="JwtVcIssuerMetadataResolutionOutcome.Resolved"/>
    /// <paramref name="resolution"/>: the inline <c>jwks</c> when the document carried one, or the key
    /// set <paramref name="resolveJwksUri"/> fetches from the document's <c>jwks_uri</c> otherwise.
    /// </summary>
    /// <param name="resolution">The resolved JWT VC Issuer Metadata configuration.</param>
    /// <param name="keyId">
    /// The Issuer-signed JWT's <c>kid</c> header. Selection runs
    /// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?, ReadOnlySpan{byte})"/>
    /// when supplied — refusing when the identifier is carried by two or more keys in the set,
    /// whatever each match's <c>use</c> is
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see>) — or
    /// <see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/> when
    /// <see langword="null"/> or empty — refusing when more than one key in the set is eligible for
    /// signature verification; a set with no <c>use</c> member on any key is refused when it carries
    /// more than one key, but a set holding one <c>sig</c> key and one <c>enc</c> key selects the
    /// <c>sig</c> key rather than refusing. Either path refuses the whole set — this library's own
    /// policy, not a requirement of any RFC — when any key in it carries private or symmetric
    /// material. Only a key eligible for signature verification is selected.
    /// </param>
    /// <param name="resolveJwksUri">The key-set fetch seam for the <c>jwks_uri</c> case.</param>
    /// <param name="context">The per-request context <paramref name="resolveJwksUri"/>'s own guarded fetch reads its policy from.</param>
    /// <param name="pool">Memory pool for the JWK Set scan and the reconstructed key material.</param>
    /// <param name="base64UrlDecoder">Decodes the selected JWK's base64url-encoded coordinates.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The selected key as a <see cref="PublicKeyMemory"/> the caller owns, or <see langword="null"/>
    /// when <paramref name="resolution"/> did not resolve, the <c>jwks_uri</c> fetch did not resolve,
    /// or no key in the set satisfies the selection query.
    /// </returns>
    public static async ValueTask<PublicKeyMemory?> SelectKeyAsync(
        JwtVcIssuerMetadataResolution resolution,
        string? keyId,
        ResolveJwksUriDelegate resolveJwksUri,
        ExchangeContext context,
        BaseMemoryPool pool,
        DecodeDelegate base64UrlDecoder,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resolution);
        ArgumentNullException.ThrowIfNull(resolveJwksUri);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);

        if(!resolution.IsResolved)
        {
            return null;
        }

        string? jwks = resolution.Jwks;
        if(jwks is null && resolution.JwksUri is not null)
        {
            JwksUriResolution jwksResolution = await resolveJwksUri(
                resolution.JwksUri, context, cancellationToken).ConfigureAwait(false);
            if(!jwksResolution.IsResolved)
            {
                return null;
            }

            jwks = jwksResolution.Jwks;
        }

        if(jwks is null)
        {
            return null;
        }

        int byteCount = Encoding.UTF8.GetByteCount(jwks);
        using IMemoryOwner<byte> jwksBytesOwner = pool.Rent(byteCount);
        Span<byte> jwksBytes = jwksBytesOwner.Memory.Span[..byteCount];
        _ = Encoding.UTF8.GetBytes(jwks, jwksBytes);

        JwkSelectionResult selection = string.IsNullOrEmpty(keyId)
            ? JwkJsonReader.SelectSoleKey(jwksBytes, WellKnownJwkValues.UseSigUtf8)
            : JwkJsonReader.SelectKeyByKeyId(jwksBytes, keyId, WellKnownJwkValues.UseSigUtf8);

        if(!selection.IsSelected)
        {
            return null;
        }

        Dictionary<string, object> jwk = FederationKeyResolver.CopyJwk(selection.Members!);

        //A selected key still is not necessarily one CryptoFormatConversions can build: a set of one
        //eligible-but-malformed element (a missing kty, or missing coordinates for its kty) reaches
        //here Selected. Refuses like every other non-Selected outcome instead of letting the
        //converter's exception escape into the verification pipeline.
        try
        {
            (CryptoAlgorithm algorithm, Purpose purpose, EncodingScheme scheme, IMemoryOwner<byte> keyMaterial) =
                CryptoFormatConversions.DefaultJwkToAlgorithmConverter(jwk, pool, base64UrlDecoder);

            Tag tag = Tag.Create(algorithm).With(purpose).With(scheme);

            return new PublicKeyMemory(keyMaterial, tag);
        }
        catch(Exception ex) when(ex is FormatException or InvalidOperationException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }


    /// <summary>
    /// Whether <paramref name="contentType"/> is <c>application/json</c> exactly, parameters (e.g.
    /// <c>;charset=utf-8</c>) stripped before comparison. Unlike <see cref="ClientIdMetadataDocuments"/>
    /// and <see cref="JwksUriResolver"/>, SD-JWT VC draft-19 §4.2 names only the bare media type —
    /// no <c>+json</c> structured-suffix allowance.
    /// </summary>
    /// <param name="contentType">The response's <c>Content-Type</c> header value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the type/subtype is <c>application/json</c>; otherwise <see langword="false"/>.</returns>
    private static bool IsApplicationJson(string? contentType)
    {
        return ContentTypeReader.ReadMediaType(contentType).Equals(
            WellKnownMediaTypes.Application.Json, StringComparison.OrdinalIgnoreCase);
    }
}

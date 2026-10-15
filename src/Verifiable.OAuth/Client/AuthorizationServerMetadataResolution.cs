using Verifiable.Core.Outbound;

namespace Verifiable.OAuth.Client;

/// <summary>
/// The closed set of metadata resolution results. Pattern-match the concrete outcome to read its
/// evidence; failures never carry a usable metadata document.
/// </summary>
public abstract class AuthorizationServerMetadataResolution
{
    /// <summary>Restricts derivation to this assembly's sealed outcomes.</summary>
    private protected AuthorizationServerMetadataResolution()
    {
    }
}


/// <summary>A parsed document whose published issuer matches the requested identifier.</summary>
public sealed class AuthorizationServerMetadataResolved : AuthorizationServerMetadataResolution
{
    /// <summary>The parsed, issuer-matched document.</summary>
    public required AuthorizationServerMetadata Metadata { get; init; }

    /// <summary>The JSON-decoded issuer, without URI normalization.</summary>
    public string PublishedIssuer => Metadata.Issuer.OriginalString;

    /// <summary>The location that supplied the document, after any permitted redirects.</summary>
    public required Uri MetadataLocation { get; init; }

    /// <summary>The storage permission and lifetime implied by the response headers.</summary>
    public HttpCacheFreshness Freshness { get; init; }
}


/// <summary>A readable document publishing a different issuer; its metadata must not be used.</summary>
public sealed class AuthorizationServerMetadataIssuerMismatch : AuthorizationServerMetadataResolution
{
    /// <summary>The identifier the caller asked to resolve.</summary>
    public required Uri RequestedIssuer { get; init; }

    /// <summary>The JSON-decoded identifier the server published, without URI normalization.</summary>
    public required string PublishedIssuer { get; init; }

    /// <summary>The location that supplied the document.</summary>
    public required Uri MetadataLocation { get; init; }
}


/// <summary>The transport failed before returning a response.</summary>
public sealed class AuthorizationServerMetadataUnreachable : AuthorizationServerMetadataResolution
{
    /// <summary>
    /// The transport exception's concrete type. The application-supplied transport's failure
    /// taxonomy is preserved without copying exception messages or retaining exceptions.
    /// </summary>
    public required Type FailureKind { get; init; }
}


/// <summary>The terminal response did not have the required HTTP 200 status.</summary>
public sealed class AuthorizationServerMetadataNotAnswered : AuthorizationServerMetadataResolution
{
    /// <summary>The status the server returned.</summary>
    public required int StatusCode { get; init; }
}


/// <summary>The guarded fetch refused to follow a redirect.</summary>
public sealed class AuthorizationServerMetadataRedirectRefused : AuthorizationServerMetadataResolution
{
    /// <summary>The redirect response's status.</summary>
    public required int StatusCode { get; init; }

    /// <summary>The refused Location header exactly as received, including relative or invalid values.</summary>
    public required string Location { get; init; }
}


/// <summary>The body exceeded the configured byte cap.</summary>
public sealed class AuthorizationServerMetadataTooLarge : AuthorizationServerMetadataResolution
{
    /// <summary>The configured maximum number of document bytes.</summary>
    public required long Limit { get; init; }

    /// <summary>The number of body bytes returned by the transport.</summary>
    public required long LengthSeen { get; init; }
}


/// <summary>The parser could not decode a metadata document.</summary>
public sealed class AuthorizationServerMetadataUnreadable : AuthorizationServerMetadataResolution
{
    /// <summary>The parser's typed failure, including the member name when applicable.</summary>
    public required AuthorizationServerMetadataParseError Error { get; init; }
}


/// <summary>The requested identifier failed RFC 8414 section 2 before any transport call.</summary>
public sealed class AuthorizationServerMetadataInvalidIssuer : AuthorizationServerMetadataResolution
{
    /// <summary>The identifier that was refused.</summary>
    public required Uri Issuer { get; init; }
}


/// <summary>The initial metadata target was denied by the outbound-fetch policy.</summary>
public sealed class AuthorizationServerMetadataPolicyDenied : AuthorizationServerMetadataResolution
{
    /// <summary>The target the policy refused before contacting the transport.</summary>
    public required Uri Target { get; init; }
}


/// <summary>The response did not declare application/json as required by RFC 8414 section 3.2.</summary>
public sealed class AuthorizationServerMetadataUnsupportedMediaType : AuthorizationServerMetadataResolution
{
    /// <summary>The received Content-Type header, or null when absent.</summary>
    public required string? ContentType { get; init; }
}

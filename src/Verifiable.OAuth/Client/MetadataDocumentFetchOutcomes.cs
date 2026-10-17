using Verifiable.Core.Outbound;

namespace Verifiable.OAuth.Client;

/// <summary>
/// The initial metadata document target was denied by the outbound-fetch policy. A fetch-outcome case type of the
/// metadata document resolutions in this namespace, carried by
/// <see cref="Verifiable.OAuth.ProtectedResource.ProtectedResourceMetadataResolution"/>.
/// </summary>
public sealed class MetadataDocumentPolicyDenied
{
    /// <summary>The target the policy refused before contacting the transport.</summary>
    public required Uri Target { get; init; }
}


/// <summary>
/// The transport failed before returning a response. A fetch-outcome case type of the metadata document resolutions in
/// this namespace, carried by <see cref="Verifiable.OAuth.ProtectedResource.ProtectedResourceMetadataResolution"/>.
/// </summary>
public sealed class MetadataDocumentUnreachable
{
    /// <summary>
    /// The guarded fetch's transport failure kind. Own-budget cancellation is classified as
    /// <see cref="TimeoutException"/>; other exception types retain the transport's taxonomy.
    /// No exception messages or instances are retained.
    /// </summary>
    public required Type FailureKind { get; init; }
}


/// <summary>
/// The guarded fetch refused to follow a redirect. A fetch-outcome case type of the metadata document resolutions in
/// this namespace, carried by <see cref="Verifiable.OAuth.ProtectedResource.ProtectedResourceMetadataResolution"/>.
/// </summary>
public sealed class MetadataDocumentRedirectRefused
{
    /// <summary>The redirect response's status.</summary>
    public required int StatusCode { get; init; }

    /// <summary>The refused Location header exactly as received, including relative or invalid values.</summary>
    public required string Location { get; init; }
}


/// <summary>
/// The body exceeded the configured byte cap. A fetch-outcome case type of the metadata document resolutions in this
/// namespace, carried by <see cref="Verifiable.OAuth.ProtectedResource.ProtectedResourceMetadataResolution"/>.
/// </summary>
public sealed class MetadataDocumentTooLarge
{
    /// <summary>The guarded fetch's declared or observed size evidence.</summary>
    public required OutboundResponseTooLarge Evidence { get; init; }

    /// <summary>The configured maximum number of document bytes.</summary>
    public long Limit => Evidence.Limit;

    /// <summary>The declared length or the observed lower bound, as identified by <see cref="LengthKind"/>.</summary>
    public long LengthSeen => Evidence.Length;

    /// <summary>Whether <see cref="LengthSeen"/> was declared or actually read.</summary>
    public OutboundResponseLengthKind LengthKind => Evidence.LengthKind;
}


/// <summary>
/// The terminal response did not have the required HTTP 200 status. A fetch-outcome case type of the metadata document
/// resolutions in this namespace, carried by
/// <see cref="Verifiable.OAuth.ProtectedResource.ProtectedResourceMetadataResolution"/>.
/// </summary>
public sealed class MetadataDocumentNotAnswered
{
    /// <summary>The status the server returned.</summary>
    public required int StatusCode { get; init; }
}


/// <summary>
/// The response did not declare the <c>application/json</c> content type the metadata document's specification
/// requires. A fetch-outcome case type of the metadata document resolutions in this namespace, carried by
/// <see cref="Verifiable.OAuth.ProtectedResource.ProtectedResourceMetadataResolution"/>.
/// </summary>
public sealed class MetadataDocumentUnsupportedMediaType
{
    /// <summary>The received Content-Type header, or null when absent.</summary>
    public required string? ContentType { get; init; }
}

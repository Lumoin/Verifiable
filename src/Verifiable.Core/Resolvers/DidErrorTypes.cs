using System;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// Standard error type URIs for DID resolution and DID URL dereferencing, as defined by the
/// W3C DID Resolution specification. Each value is a URI used as the
/// <see cref="DidProblemDetails.Type"/> discriminator in resolution metadata.
/// </summary>
/// <remarks>
/// <para>
/// Conforming DID resolvers MUST return these exact URIs in
/// <see cref="DidResolutionMetadata.Error"/> and <see cref="DidDereferencingMetadata.Error"/>
/// when the corresponding error condition is encountered.
/// </para>
/// <para>
/// The constants are typed as <see cref="Uri"/> rather than <see cref="string"/> so that
/// assignment to <see cref="DidProblemDetails.Type"/> is type-safe, and rather than
/// <c>DidUrl</c> because these are plain HTTPS URIs — they carry no DID method structure,
/// so the DID URL parser would correctly reject them.
/// </para>
/// <para>
/// See <see href="https://w3c.github.io/did-resolution/#errors">DID Resolution §9 Errors</see>
/// for the normative list of error types.
/// </para>
/// </remarks>
public static class DidErrorTypes
{
    /// <summary>
    /// The W3C DID namespace URI prefix for all standard error type values.
    /// </summary>
    private const string Namespace = "https://www.w3.org/ns/did#";

    /// <summary>
    /// The input DID does not conform to the DID syntax rules.
    /// </summary>
    public static readonly Uri InvalidDid = new(Namespace + "INVALID_DID");

    /// <summary>
    /// The DID document was malformed.
    /// </summary>
    public static readonly Uri InvalidDidDocument = new(Namespace + "INVALID_DID_DOCUMENT");

    /// <summary>
    /// The DID does not exist in its verifiable data registry.
    /// </summary>
    public static readonly Uri NotFound = new(Namespace + "NOT_FOUND");

    /// <summary>
    /// The representation requested via the <c>accept</c> input metadata property is not
    /// supported by the DID method and/or DID resolver implementation.
    /// </summary>
    public static readonly Uri RepresentationNotSupported = new(Namespace + "REPRESENTATION_NOT_SUPPORTED");

    /// <summary>
    /// The input DID URL does not conform to the DID URL syntax rules.
    /// </summary>
    public static readonly Uri InvalidDidUrl = new(Namespace + "INVALID_DID_URL");

    /// <summary>
    /// The DID method used by the input DID is not supported by this resolver.
    /// </summary>
    public static readonly Uri MethodNotSupported = new(Namespace + "METHOD_NOT_SUPPORTED");

    /// <summary>
    /// One or more of the supplied resolution or dereferencing options are invalid.
    /// </summary>
    public static readonly Uri InvalidOptions = new(Namespace + "INVALID_OPTIONS");

    /// <summary>
    /// An unexpected error occurred during resolution or dereferencing.
    /// </summary>
    public static readonly Uri InternalError = new(Namespace + "INTERNAL_ERROR");

    /// <summary>
    /// The DID resolver does not support the requested feature. The <c>detail</c> field
    /// SHOULD describe which feature is unsupported.
    /// </summary>
    public static readonly Uri FeatureNotSupported = new(Namespace + "FEATURE_NOT_SUPPORTED");
}

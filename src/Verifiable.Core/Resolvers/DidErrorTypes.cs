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
/// See <see href="https://www.w3.org/TR/did-resolution/#errors">DID Resolution §9 Errors</see>
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

    /// <summary>
    /// A DID URL dereferenced to a resource that is not a conforming verification method, or
    /// whose <c>id</c> or <c>controller</c> does not match the controller document. Raised by
    /// the Retrieve Verification Method algorithm.
    /// </summary>
    /// <remarks>
    /// See <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID 1.0 §3.3
    /// Retrieve Verification Method</see> (steps 8–10), surfaced through
    /// <see href="https://www.w3.org/TR/did-resolution/#dereferencing-secondary-resource">DID
    /// Resolution §5.4.2</see>.
    /// </remarks>
    public static readonly Uri InvalidVerificationMethod = new(Namespace + "INVALID_VERIFICATION_METHOD");

    /// <summary>
    /// A DID URL dereferenced to a verification method that is not associated, either by
    /// reference or by value, with the verification relationship the caller requested. Raised by
    /// the Retrieve Verification Method algorithm.
    /// </summary>
    /// <remarks>
    /// See <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID 1.0 §3.3
    /// Retrieve Verification Method</see> (step 11), surfaced through
    /// <see href="https://www.w3.org/TR/did-resolution/#dereferencing-secondary-resource">DID
    /// Resolution §5.4.2</see>.
    /// </remarks>
    public static readonly Uri InvalidRelationshipForVerificationMethod = new(Namespace + "INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD");

    /// <summary>
    /// Maps a standard DID error type URI to the lowerCamelCase string code the W3C DID Resolution and the
    /// did:webvh specification require in the metadata <c>error</c> field (for example
    /// <c>#NOT_FOUND</c> -&gt; <c>notFound</c>, <c>#INVALID_DID</c> -&gt; <c>invalidDid</c>,
    /// <c>#METHOD_NOT_SUPPORTED</c> -&gt; <c>methodNotSupported</c>). An unrecognized type URI maps to
    /// <c>internalError</c>.
    /// </summary>
    /// <param name="type">The error type URI, one of the values defined in this class.</param>
    /// <returns>The lowerCamelCase error code string for the metadata <c>error</c> field.</returns>
    public static string ToErrorCode(Uri type)
    {
        ArgumentNullException.ThrowIfNull(type);

        return type.AbsoluteUri switch
        {
            var uri when uri == InvalidDid.AbsoluteUri => "invalidDid",
            var uri when uri == InvalidDidDocument.AbsoluteUri => "invalidDidDocument",
            var uri when uri == NotFound.AbsoluteUri => "notFound",
            var uri when uri == RepresentationNotSupported.AbsoluteUri => "representationNotSupported",
            var uri when uri == InvalidDidUrl.AbsoluteUri => "invalidDidUrl",
            var uri when uri == MethodNotSupported.AbsoluteUri => "methodNotSupported",
            var uri when uri == InvalidOptions.AbsoluteUri => "invalidOptions",
            var uri when uri == InternalError.AbsoluteUri => "internalError",
            var uri when uri == FeatureNotSupported.AbsoluteUri => "featureNotSupported",
            var uri when uri == InvalidVerificationMethod.AbsoluteUri => "invalidVerificationMethod",
            var uri when uri == InvalidRelationshipForVerificationMethod.AbsoluteUri => "invalidRelationshipForVerificationMethod",
            _ => "internalError"
        };
    }


    /// <summary>
    /// Maps a lowerCamelCase error code string (as written in the metadata <c>error</c> field) back to its
    /// standard DID error type URI. The inverse of <see cref="ToErrorCode"/>; an unrecognized code maps to
    /// <see cref="InternalError"/>.
    /// </summary>
    /// <param name="code">The lowerCamelCase error code string.</param>
    /// <returns>The standard error type URI for the code.</returns>
    public static Uri FromErrorCode(string code)
    {
        ArgumentNullException.ThrowIfNull(code);

        return code switch
        {
            "invalidDid" => InvalidDid,
            "invalidDidDocument" => InvalidDidDocument,
            "notFound" => NotFound,
            "representationNotSupported" => RepresentationNotSupported,
            "invalidDidUrl" => InvalidDidUrl,
            "methodNotSupported" => MethodNotSupported,
            "invalidOptions" => InvalidOptions,
            "internalError" => InternalError,
            "featureNotSupported" => FeatureNotSupported,
            "invalidVerificationMethod" => InvalidVerificationMethod,
            "invalidRelationshipForVerificationMethod" => InvalidRelationshipForVerificationMethod,
            _ => InternalError
        };
    }
}

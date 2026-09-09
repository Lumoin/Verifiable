namespace Verifiable.Core.Resolvers;

/// <summary>
/// Pre-built <see cref="DidProblemDetails"/> instances for the standard error conditions
/// defined in the W3C DID Resolution specification.
/// </summary>
/// <remarks>
/// <para>
/// These instances are returned directly by <see cref="DidResolver"/> and by the
/// <see cref="DidResolutionResult.Failure"/> and <see cref="DidDereferencingResult.Failure"/>
/// factory methods. Because <see cref="DidProblemDetails"/> is a <c>sealed record</c> with
/// value equality on <see cref="DidProblemDetails.Type"/>, test assertions can compare against
/// these shared instances or against any instance carrying the same type URI.
/// </para>
/// <para>
/// Callers that need to attach a context-specific <c>Detail</c> or <c>Instance</c> should
/// construct a new <see cref="DidProblemDetails"/> using the appropriate
/// <see cref="DidErrorTypes"/> URI rather than using these defaults.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/did-resolution/#errors">DID Resolution §9 Errors</see>.
/// </para>
/// </remarks>
public static class DidResolutionErrors
{
    /// <summary>
    /// The input DID does not conform to the DID syntax rules.
    /// </summary>
    public static DidProblemDetails InvalidDid { get; } = new(
        DidErrorTypes.InvalidDid,
        Title: "Invalid DID");

    /// <summary>
    /// The DID document was malformed.
    /// </summary>
    public static DidProblemDetails InvalidDidDocument { get; } = new(
        DidErrorTypes.InvalidDidDocument,
        Title: "Invalid DID document");

    /// <summary>
    /// The DID does not exist in its verifiable data registry.
    /// </summary>
    public static DidProblemDetails NotFound { get; } = new(
        DidErrorTypes.NotFound,
        Title: "Not found");

    /// <summary>
    /// The representation requested via the <c>accept</c> input metadata property is not
    /// supported by the DID method and/or DID resolver implementation.
    /// </summary>
    public static DidProblemDetails RepresentationNotSupported { get; } = new(
        DidErrorTypes.RepresentationNotSupported,
        Title: "Representation not supported");

    /// <summary>
    /// The input DID URL does not conform to the DID URL syntax rules.
    /// </summary>
    public static DidProblemDetails InvalidDidUrl { get; } = new(
        DidErrorTypes.InvalidDidUrl,
        Title: "Invalid DID URL");

    /// <summary>
    /// The DID method used by the input DID is not supported by this resolver.
    /// </summary>
    public static DidProblemDetails MethodNotSupported { get; } = new(
        DidErrorTypes.MethodNotSupported,
        Title: "Method not supported");

    /// <summary>
    /// One or more of the supplied resolution or dereferencing options are invalid.
    /// </summary>
    public static DidProblemDetails InvalidOptions { get; } = new(
        DidErrorTypes.InvalidOptions,
        Title: "Invalid options");

    /// <summary>
    /// An unexpected error occurred during resolution or dereferencing.
    /// </summary>
    public static DidProblemDetails InternalError { get; } = new(
        DidErrorTypes.InternalError,
        Title: "Internal error");

    /// <summary>
    /// The DID resolver does not support the requested feature.
    /// </summary>
    public static DidProblemDetails FeatureNotSupported { get; } = new(
        DidErrorTypes.FeatureNotSupported,
        Title: "Feature not supported");

    /// <summary>
    /// A DID URL dereferenced to a resource that is not a conforming verification method, or
    /// whose <c>id</c> or <c>controller</c> does not match the controller document
    /// (CID 1.0 §3.3 steps 8–10).
    /// </summary>
    public static DidProblemDetails InvalidVerificationMethod { get; } = new(
        DidErrorTypes.InvalidVerificationMethod,
        Title: "Invalid verification method");

    /// <summary>
    /// A DID URL dereferenced to a verification method that is not associated with the requested
    /// verification relationship (CID 1.0 §3.3 step 11).
    /// </summary>
    public static DidProblemDetails InvalidRelationshipForVerificationMethod { get; } = new(
        DidErrorTypes.InvalidRelationshipForVerificationMethod,
        Title: "Invalid relationship for verification method");
}

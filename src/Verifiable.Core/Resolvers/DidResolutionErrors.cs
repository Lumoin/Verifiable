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
/// See <see href="https://w3c.github.io/did-resolution/#errors">DID Resolution §9 Errors</see>.
/// </para>
/// </remarks>
public static class DidResolutionErrors
{
    /// <summary>
    /// The input DID does not conform to the DID syntax rules.
    /// </summary>
    public static readonly DidProblemDetails InvalidDid = new(
        DidErrorTypes.InvalidDid,
        Title: "Invalid DID");

    /// <summary>
    /// The DID document was malformed.
    /// </summary>
    public static readonly DidProblemDetails InvalidDidDocument = new(
        DidErrorTypes.InvalidDidDocument,
        Title: "Invalid DID document");

    /// <summary>
    /// The DID does not exist in its verifiable data registry.
    /// </summary>
    public static readonly DidProblemDetails NotFound = new(
        DidErrorTypes.NotFound,
        Title: "Not found");

    /// <summary>
    /// The representation requested via the <c>accept</c> input metadata property is not
    /// supported by the DID method and/or DID resolver implementation.
    /// </summary>
    public static readonly DidProblemDetails RepresentationNotSupported = new(
        DidErrorTypes.RepresentationNotSupported,
        Title: "Representation not supported");

    /// <summary>
    /// The input DID URL does not conform to the DID URL syntax rules.
    /// </summary>
    public static readonly DidProblemDetails InvalidDidUrl = new(
        DidErrorTypes.InvalidDidUrl,
        Title: "Invalid DID URL");

    /// <summary>
    /// The DID method used by the input DID is not supported by this resolver.
    /// </summary>
    public static readonly DidProblemDetails MethodNotSupported = new(
        DidErrorTypes.MethodNotSupported,
        Title: "Method not supported");

    /// <summary>
    /// One or more of the supplied resolution or dereferencing options are invalid.
    /// </summary>
    public static readonly DidProblemDetails InvalidOptions = new(
        DidErrorTypes.InvalidOptions,
        Title: "Invalid options");

    /// <summary>
    /// An unexpected error occurred during resolution or dereferencing.
    /// </summary>
    public static readonly DidProblemDetails InternalError = new(
        DidErrorTypes.InternalError,
        Title: "Internal error");

    /// <summary>
    /// The DID resolver does not support the requested feature.
    /// </summary>
    public static readonly DidProblemDetails FeatureNotSupported = new(
        DidErrorTypes.FeatureNotSupported,
        Title: "Feature not supported");
}

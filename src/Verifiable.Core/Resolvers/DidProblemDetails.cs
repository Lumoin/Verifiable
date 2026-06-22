using System;
using System.Diagnostics;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// An RFC 9457 Problem Details object used as the <c>error</c> value in
/// <see cref="DidResolutionMetadata"/> and <see cref="DidDereferencingMetadata"/>.
/// </summary>
/// <remarks>
/// <para>
/// The W3C DID Resolution specification requires that the <c>error</c> property in resolution
/// and dereferencing metadata be an RFC 9457 Problem Details structure. The <see cref="Type"/>
/// property is the primary discriminator and MUST be one of the URIs defined in
/// <see cref="DidErrorTypes"/> for standard error conditions.
/// </para>
/// <para>
/// Value equality is defined on <see cref="Type"/> alone so that pre-built instances in
/// <see cref="DidResolutionErrors"/> compare equal to any instance carrying the same type URI,
/// regardless of the optional human-readable fields.
/// </para>
/// <para>
/// See <see href="https://www.rfc-editor.org/rfc/rfc9457">RFC 9457 Problem Details for HTTP APIs</see>
/// and <see href="https://w3c.github.io/did-resolution/#errors">W3C DID Resolution §9 Errors</see>.
/// </para>
/// </remarks>
/// <param name="Type">
/// A URI reference that identifies the problem type. For standard DID Resolution errors this
/// MUST be one of the URIs defined in <see cref="DidErrorTypes"/>.
/// </param>
/// <param name="Title">
/// A short, human-readable summary of the problem type. SHOULD not change between occurrences
/// of the same error type.
/// </param>
/// <param name="Status">
/// The HTTP status code associated with this problem, if applicable.
/// </param>
/// <param name="Detail">
/// A longer human-readable explanation specific to this occurrence of the problem.
/// </param>
/// <param name="Instance">
/// A URI reference that identifies the specific occurrence of the problem.
/// </param>
[DebuggerDisplay("{Type.AbsoluteUri,nq} {Title,nq}")]
public sealed record DidProblemDetails(
    Uri Type,
    string? Title = null,
    int? Status = null,
    string? Detail = null,
    Uri? Instance = null)
{
    /// <summary>
    /// The lowerCamelCase error code derived from <see cref="Type"/> for the metadata <c>error</c> field (for
    /// example <c>invalidDid</c>, <c>notFound</c>, <c>methodNotSupported</c>). The RFC 9457 object itself is
    /// carried separately in the metadata <c>problemDetails</c> field (did:webvh v1.0, error envelope: L872).
    /// </summary>
    public string Code => DidErrorTypes.ToErrorCode(Type);


    /// <summary>
    /// Equality is on <see cref="Type"/> alone, so a pre-built <see cref="DidResolutionErrors"/> instance
    /// compares equal to any instance carrying the same problem-type URI regardless of the optional
    /// human-readable fields (an occurrence-specific <see cref="Detail"/> does not change the error identity).
    /// </summary>
    /// <param name="other">The instance to compare against.</param>
    /// <returns><see langword="true"/> when both carry the same problem-type URI.</returns>
    public bool Equals(DidProblemDetails? other)
    {
        //Compare the full URI string, NOT Uri.Equals: Uri value-equality ignores the fragment, but the DID
        //Resolution error types differ ONLY by fragment (https://www.w3.org/ns/did#NOT_FOUND vs #INVALID_DID),
        //so Uri.Equals would collapse every error type to one identity. Equality stays on the type alone — an
        //occurrence-specific Detail/Title/Status/Instance does not change the error identity.
        return other is not null && string.Equals(Type.AbsoluteUri, other.Type.AbsoluteUri, StringComparison.Ordinal);
    }


    /// <inheritdoc />
    public override int GetHashCode()
    {
        return StringComparer.Ordinal.GetHashCode(Type.AbsoluteUri);
    }
}
